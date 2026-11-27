package db

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type endpointIdentity struct {
	ServiceURL   string
	URL          string
	Path         string
	PathTemplate string
	Params       []map[string]any
	Uncertain    bool
}

// CanonicalEndpointURL is the URL part of an endpoint's natural key. Request
// samples belong to evidence; query values and fragments never identify assets.
func CanonicalEndpointURL(raw string) (string, error) {
	identity, err := identifyEndpoint(raw)
	return identity.URL, err
}

// ensureEndpointService returns the HTTP service asset owning the endpoint's
// origin, creating it on first sight. Endpoints reference their service through
// assets.service_id: the self-reference keeps existing rows, archives and
// scoped queries working without a join table, and the service row already has
// the URL uniqueness constraint we need.
func (s *AssetStore) ensureEndpointService(serviceURL string, taskID int64) (int64, error) {
	id, err := findHTTPServiceID(s.tx, serviceURL)
	if err == nil {
		if taskID > 0 {
			_, err = s.tx.Exec(`UPDATE assets SET task_ids=json_array_union(task_ids,json_array($2)) WHERE id=$1`, id, taskID)
		}
		return id, err
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	return s.UpsertHTTPService(UpsertHTTPServiceReq{URL: serviceURL, TaskID: taskID})
}

func findHTTPServiceID(tx *sql.Tx, serviceURL string) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM assets WHERE type='service' AND service_type='http' AND url=$1`, serviceURL).Scan(&id)
	if err == nil || err != sql.ErrNoRows {
		return id, err
	}
	rows, err := tx.Query(`SELECT id, url FROM assets WHERE type='service' AND service_type='http' ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var candidateID int64
		var rawURL string
		if err := rows.Scan(&candidateID, &rawURL); err != nil {
			return 0, err
		}
		if canonicalHTTPServiceURL(rawURL) == serviceURL {
			return candidateID, nil
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return 0, sql.ErrNoRows
}

// canonicalHTTPServiceURL normalizes only the service identity. Unlike an
// endpoint, a service may intentionally retain a base path, so path segments
// are not templated here.
func canonicalHTTPServiceURL(raw string) string {
	identity, err := identifyEndpoint(raw)
	if err != nil {
		return normalizeURL(raw)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return normalizeURL(raw)
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return identity.ServiceURL
	}
	return identity.ServiceURL + path
}

// endpointInTaskScope treats an unconfigured scope as legacy/open behavior,
// but once a task has explicit scope rows every confirmed observation must
// match one of them. Candidates outside the scope are still retained by the
// caller with an unresolved reason; they never promote an asset.
func endpointInTaskScope(tx *sql.Tx, taskID int64, serviceURL string) (bool, error) {
	var scopeCount int
	if err := tx.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1`, taskID).Scan(&scopeCount); err != nil {
		return false, err
	}
	if scopeCount == 0 {
		return true, nil
	}
	u, err := url.Parse(serviceURL)
	if err != nil || u.Hostname() == "" {
		return false, nil
	}
	host := DomainKey(u.Hostname())
	root, _ := RootDomain(host)
	if root == "" {
		root = host
	}
	ip := net.ParseIP(host)
	serviceID, serviceErr := findHTTPServiceID(tx, serviceURL)
	var companyID sql.NullInt64
	var serviceIP string
	if serviceErr == nil {
		if err := tx.QueryRow(`SELECT company_id, COALESCE(ip,'') FROM assets WHERE id=$1`, serviceID).Scan(&companyID, &serviceIP); err != nil && err != sql.ErrNoRows {
			return false, err
		}
	} else if serviceErr != sql.ErrNoRows {
		return false, serviceErr
	}
	serviceAddr := net.ParseIP(strings.TrimSpace(serviceIP))
	rows, err := tx.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net,''), COALESCE(company_id,0)
FROM task_scope WHERE task_id=$1`, taskID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, domain, network string
		var scopeCompany int64
		if err := rows.Scan(&kind, &domain, &network, &scopeCompany); err != nil {
			return false, err
		}
		switch kind {
		case "root_domain":
			if DomainKey(domain) == root {
				return true, nil
			}
		case "subdomain":
			if DomainKey(domain) == host {
				return true, nil
			}
		case "ip", "cidr":
			_, cidr, parseErr := net.ParseCIDR(network)
			if parseErr == nil {
				if (ip != nil && cidr.Contains(ip)) || (serviceAddr != nil && cidr.Contains(serviceAddr)) {
					return true, nil
				}
			}
		case "company":
			if companyID.Valid && scopeCompany > 0 && companyID.Int64 == scopeCompany {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func identifyEndpoint(raw string) (endpointIdentity, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return endpointIdentity{}, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return endpointIdentity{}, fmt.Errorf("endpoint URL must be absolute HTTP(S)")
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return endpointIdentity{}, fmt.Errorf("invalid endpoint port %q", port)
		}
		if n == defaultPort(u.Scheme, "") {
			port = ""
		} else {
			port = strconv.Itoa(n)
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	// Keep encoded slashes distinct from path separators while accepting our
	// own stored templates on a subsequent upsert or archive restore.
	path = strings.ReplaceAll(strings.ReplaceAll(path, "%7B", "{"), "%7D", "}")
	template := TemplatePath(path)
	identity := endpointIdentity{ServiceURL: u.Scheme + "://" + host, Path: path, PathTemplate: template}
	identity.URL = identity.ServiceURL + template
	for _, segment := range strings.Split(path, "/") {
		// A long resource word or an unresolved code expression is not enough
		// evidence to invent a dynamic route segment.
		if (reLong.MatchString(segment) && !reDigit.MatchString(segment)) || strings.ContainsAny(segment, "$*:") {
			identity.Uncertain = true
		}
	}
	for _, segment := range strings.Split(template, "/") {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			identity.Params = append(identity.Params, map[string]any{"location": "path", "name": strings.Trim(segment, "{}"), "type": "string"})
		}
	}
	names := make([]string, 0, len(u.Query()))
	for name := range u.Query() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		identity.Params = append(identity.Params, map[string]any{"location": "query", "name": name})
	}
	return identity, nil
}
