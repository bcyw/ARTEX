package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// EndpointObservation is shared by static inventory, browser and traffic
// importers. Only an observed method (or explicit manual confirmation) promotes
// a candidate. Params describe shape; evidence locates the original sample.
type EndpointObservation struct {
	TaskID          int64            `json:"task_id"`
	ServiceURL      string           `json:"service_url,omitempty"`
	URL             string           `json:"url"`
	Path            string           `json:"path"`
	PathTemplate    string           `json:"path_template"`
	Method          string           `json:"method,omitempty"`
	MethodCandidate bool             `json:"method_candidate,omitempty"`
	Source          string           `json:"source"`
	Params          []map[string]any `json:"params"`
	Evidence        []map[string]any `json:"evidence,omitempty"`
	ObservedAt      time.Time        `json:"observed_at"`
	ParseStatus     string           `json:"parse_status"`
	Reason          string           `json:"reason,omitempty"`
}

type EndpointCandidate struct {
	ID           int64                 `json:"id"`
	TaskID       int64                 `json:"task_id"`
	ServiceURL   string                `json:"service_url"`
	PathTemplate string                `json:"path_template"`
	Method       string                `json:"method"`
	Params       []map[string]any      `json:"params"`
	Observations []EndpointObservation `json:"observations"`
	Status       string                `json:"status"`
	Reason       string                `json:"reason,omitempty"`
	AssetID      int64                 `json:"asset_id,omitempty"`
}

// RecordEndpointObservation atomically records provenance and, when confirmed,
// merges parameters into the global endpoint. It does not change task scope.
func (s *AssetStore) RecordEndpointObservation(obs EndpointObservation) (candidateID, assetID int64, err error) {
	if obs.TaskID <= 0 {
		return 0, 0, fmt.Errorf("endpoint observation requires a task")
	}
	switch obs.Source {
	case "static", "runtime", "traffic", "manual":
	default:
		return 0, 0, fmt.Errorf("invalid endpoint observation source %q", obs.Source)
	}
	if s.tx == nil {
		_, err = s.withCompanyScopeMutation(func(scoped *AssetStore) (int64, error) {
			var writeErr error
			candidateID, assetID, writeErr = scoped.RecordEndpointObservation(obs)
			return candidateID, writeErr
		})
		return candidateID, assetID, err
	}
	identity, err := identifyEndpoint(obs.URL)
	if err != nil {
		safeURL := endpointObservationURL(obs.URL)
		path := unresolvedEndpointPath(safeURL)
		identity = endpointIdentity{ServiceURL: endpointObservationURL(obs.ServiceURL), Path: path, PathTemplate: path, Uncertain: true}
		obs.ParseStatus = "unresolved"
		if obs.Reason == "" {
			// Parser errors often echo the complete URL, including userinfo and
			// query credentials. Keep the diagnostic useful without copying input.
			obs.Reason = "endpoint URL could not be parsed as absolute HTTP(S)"
		}
	} else if obs.ServiceURL != "" {
		expected, expectedErr := identifyEndpoint(obs.ServiceURL)
		if expectedErr != nil || expected.ServiceURL != identity.ServiceURL {
			obs.ParseStatus, obs.Reason = "unresolved", "observed host differs from the supplied HTTP service"
		}
	}
	if identity.Uncertain && (obs.ParseStatus == "" || obs.ParseStatus == "parsed") {
		obs.ParseStatus = "uncertain"
		obs.Reason = "path cannot be reliably generalized"
	}
	if identity.ServiceURL != "" {
		inScope, err := endpointInTaskScope(s.tx, obs.TaskID, identity.ServiceURL)
		if err != nil {
			return 0, 0, err
		}
		if !inScope {
			obs.ParseStatus = "unresolved"
			obs.Reason = "observed host is outside task scope"
		}
	}
	obs.ServiceURL, obs.Path, obs.PathTemplate = identity.ServiceURL, identity.Path, identity.PathTemplate
	obs.URL = endpointObservationURL(obs.URL)
	refs, err := json.Marshal(obs.Evidence)
	if err != nil {
		return 0, 0, err
	}
	var evidence any
	if err := json.Unmarshal(refs, &evidence); err != nil {
		return 0, 0, err
	}
	obs.Evidence = nil
	for _, ref := range cleanEndpointEvidence(evidence) {
		obs.Evidence = append(obs.Evidence, ref.(map[string]any))
	}
	obs.Method = strings.ToUpper(strings.TrimSpace(obs.Method))
	missingObservedAt := obs.ObservedAt.IsZero()
	if missingObservedAt {
		obs.ObservedAt = time.Now().UTC()
	}
	if obs.ParseStatus == "" {
		obs.ParseStatus = "parsed"
	}
	confirm := obs.Method != "" && !obs.MethodCandidate && obs.ParseStatus == "parsed" && (obs.Source != "static" || hasEndpointCodeLocation(obs.Evidence))
	if !confirm && obs.Reason == "" {
		obs.Reason = "awaiting observed HTTP method"
	}
	// Attach observation provenance to inferred parameters as well as supplied
	// parameters, without mutating the caller's maps.
	params := make([]map[string]any, 0, len(identity.Params)+len(obs.Params))
	for _, item := range append(identity.Params, obs.Params...) {
		p := map[string]any{"source": obs.Source, "evidence": obs.Evidence}
		for key, value := range item {
			p[key] = value
		}
		params = append(params, p)
	}
	paramsJSON, err := endpointParamsJSON(params)
	if err != nil {
		return 0, 0, err
	}
	if err = json.Unmarshal([]byte(paramsJSON), &obs.Params); err != nil {
		return 0, 0, err
	}
	method := obs.Method
	// Late static inventory may omit a method already confirmed by this task.
	// Reuse only an unambiguous method; two confirmed methods still need an
	// unknown-method candidate rather than guessing which one was intended.
	var confirmedCount int
	var confirmedMethod string
	if err := s.tx.QueryRow(`SELECT count(DISTINCT method), COALESCE(min(method),'') FROM endpoint_candidates
WHERE task_id=$1 AND service_url=$2 AND path_template=$3 AND asset_id IS NOT NULL AND status='confirmed' AND method<>''`, obs.TaskID, obs.ServiceURL, obs.PathTemplate).Scan(&confirmedCount, &confirmedMethod); err != nil {
		return 0, 0, err
	}
	if method == "" && !obs.MethodCandidate && obs.ParseStatus == "parsed" {
		if confirmedCount == 1 {
			method = confirmedMethod
		}
	}
	canFoldUnknown := method != "" && (confirmedCount == 0 || (confirmedCount == 1 && confirmedMethod == method))
	reuseUnknown := canFoldUnknown && (confirm || method != obs.Method)
	// Prefer an exact method, otherwise reuse the unknown candidate on first
	// confirmation. Conflicting known methods keep their own provenance.
	err = s.tx.QueryRow(`SELECT id FROM endpoint_candidates
 WHERE task_id=$1 AND service_url=$2 AND path_template=$3
	AND (method=$4 OR (method='' AND status='pending' AND $5))
	AND ($6=FALSE OR status='pending')
	ORDER BY (method=$4) DESC, id LIMIT 1`, obs.TaskID, obs.ServiceURL, obs.PathTemplate, method, reuseUnknown, obs.MethodCandidate).Scan(&candidateID)
	preserveConfirmedCandidate := false
	if err != nil && err != sql.ErrNoRows {
		return 0, 0, err
	}
	if err == sql.ErrNoRows {
		// The schema permits one candidate per route/method. Preserve a later
		// speculative observation on an already-confirmed row without merging its
		// parameters into the confirmed candidate or global asset.
		if obs.MethodCandidate && method != "" {
			err = s.tx.QueryRow(`SELECT id FROM endpoint_candidates
WHERE task_id=$1 AND service_url=$2 AND path_template=$3 AND method=$4
  AND status='confirmed' AND asset_id IS NOT NULL
ORDER BY id LIMIT 1`, obs.TaskID, obs.ServiceURL, obs.PathTemplate, method).Scan(&candidateID)
			if err == nil {
				preserveConfirmedCandidate = true
			} else if err != sql.ErrNoRows {
				return 0, 0, err
			}
		}
		if !preserveConfirmedCandidate {
			err = s.tx.QueryRow(`INSERT INTO endpoint_candidates(task_id, service_url, path_template, method)
VALUES($1,$2,$3,$4) RETURNING id`, obs.TaskID, obs.ServiceURL, obs.PathTemplate, method).Scan(&candidateID)
			if err != nil {
				return 0, 0, err
			}
		}
	}
	if reuseUnknown {
		// An exact-method and an unknown-method candidate can predate the same
		// confirmation. Fold both histories before removing the competing row.
		var unknownID int64
		err := s.tx.QueryRow(`SELECT id FROM endpoint_candidates WHERE task_id=$1 AND service_url=$2 AND path_template=$3 AND method='' AND id<>$4`, obs.TaskID, obs.ServiceURL, obs.PathTemplate, candidateID).Scan(&unknownID)
		if err != nil && err != sql.ErrNoRows {
			return 0, 0, err
		}
		if err == nil {
			if _, err := s.tx.Exec(`UPDATE endpoint_candidates SET params=json_merge_params(params,(SELECT params FROM endpoint_candidates WHERE id=$2)), observations=json_array_union(observations,(SELECT observations FROM endpoint_candidates WHERE id=$2)) WHERE id=$1`, candidateID, unknownID); err != nil {
				return 0, 0, err
			}
			if _, err := s.tx.Exec(`DELETE FROM endpoint_candidates WHERE id=$1`, unknownID); err != nil {
				return 0, 0, err
			}
		}
	}
	if missingObservedAt {
		var existing []EndpointObservation
		var rawExisting []byte
		if err := s.tx.QueryRow(`SELECT observations FROM endpoint_candidates WHERE id=$1`, candidateID).Scan(&rawExisting); err != nil {
			return 0, 0, err
		}
		if err := json.Unmarshal(rawExisting, &existing); err != nil {
			return 0, 0, err
		}
		for _, previous := range existing {
			if endpointObservationEqual(previous, obs) {
				obs.ObservedAt = previous.ObservedAt
				break
			}
		}
	}
	observations, err := json.Marshal([]EndpointObservation{obs})
	if err != nil {
		return 0, 0, err
	}
	if preserveConfirmedCandidate {
		if err := s.tx.QueryRow(`UPDATE endpoint_candidates
SET observations=json_array_union(observations,$2)
WHERE id=$1 RETURNING COALESCE(asset_id,0)`, candidateID, string(observations)).Scan(&assetID); err != nil {
			return 0, 0, err
		}
		return candidateID, 0, nil
	}
	var merged []byte
	err = s.tx.QueryRow(`UPDATE endpoint_candidates SET method=$2,
params=json_merge_params(params,$3), observations=json_array_union(observations,$4),
reason=CASE WHEN status='confirmed' THEN reason ELSE $5 END
WHERE id=$1 RETURNING params, COALESCE(asset_id,0)`, candidateID, method, paramsJSON, string(observations), obs.Reason).Scan(&merged, &assetID)
	if err != nil {
		return 0, 0, err
	}
	if confirm {
		if err = json.Unmarshal(merged, &params); err != nil {
			return 0, 0, err
		}
		assetID, err = s.UpsertEndpoint(UpsertEndpointReq{URL: identity.URL, Method: method, Params: params, TaskID: obs.TaskID})
		if err != nil {
			return 0, 0, err
		}
		_, err = s.tx.Exec(`UPDATE endpoint_candidates SET status='confirmed', reason='', asset_id=$2 WHERE id=$1`, candidateID, assetID)
	}
	return candidateID, assetID, err
}

func endpointObservationEqual(left, right EndpointObservation) bool {
	left.ObservedAt, right.ObservedAt = time.Time{}, time.Time{}
	a, err := json.Marshal(left)
	if err != nil {
		return false
	}
	b, err := json.Marshal(right)
	return err == nil && bytes.Equal(a, b)
}

func hasEndpointCodeLocation(evidence []map[string]any) bool {
	for _, ref := range evidence {
		if location, ok := ref["code_location"].(string); ok && strings.TrimSpace(location) != "" {
			return true
		}
	}
	return false
}

func unresolvedEndpointPath(raw string) string {
	safe := endpointObservationURL(raw)
	if u, err := url.Parse(safe); err == nil {
		if path := u.EscapedPath(); path != "" {
			return path
		}
	}
	if i := strings.IndexAny(safe, "?#"); i >= 0 {
		safe = safe[:i]
	}
	return safe
}

// Keep the original route and non-sensitive query context, but never copy URL
// credentials into observation JSON. Raw requests stay in the evidence store.
func endpointObservationURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactMalformedEndpointURL(raw)
	}
	u.User, u.Fragment = nil, ""
	query := u.Query()
	for name := range query {
		if sensitiveEndpointQueryName(name) {
			query.Set(name, "[redacted]")
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func redactMalformedEndpointURL(raw string) string {
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = raw[:i]
	}
	authorityStart := -1
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		authorityStart = scheme + len("://")
	} else if strings.HasPrefix(raw, "//") {
		authorityStart = len("//")
	}
	if authorityStart >= 0 {
		authorityEnd := len(raw)
		if i := strings.IndexAny(raw[authorityStart:], "/?"); i >= 0 {
			authorityEnd = authorityStart + i
		}
		if at := strings.LastIndex(raw[authorityStart:authorityEnd], "@"); at >= 0 {
			raw = raw[:authorityStart] + raw[authorityStart+at+1:]
		}
	}
	question := strings.IndexByte(raw, '?')
	if question < 0 {
		return raw
	}
	parts := strings.Split(raw[question+1:], "&")
	for i, part := range parts {
		name, _, hasValue := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(name)
		if err != nil {
			decoded = name
		}
		if hasValue && sensitiveEndpointQueryName(decoded) {
			parts[i] = name + "=%5Bredacted%5D"
		}
	}
	return raw[:question+1] + strings.Join(parts, "&")
}

func sensitiveEndpointQueryName(name string) bool {
	lower := strings.ToLower(name)
	for _, sensitive := range []string{"token", "cookie", "authorization", "password", "passwd", "pwd", "secret", "key", "session", "signature", "auth"} {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

func (s *AssetStore) ListEndpointCandidates(taskID int64, status string) ([]*EndpointCandidate, error) {
	rows, err := s.db.Query(`SELECT id, task_id, service_url, path_template, method, params, observations,
status, reason, COALESCE(asset_id,0) FROM endpoint_candidates WHERE task_id=$1 AND ($2='' OR status=$2) ORDER BY id`, taskID, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*EndpointCandidate{}
	for rows.Next() {
		c := &EndpointCandidate{}
		var params, observations []byte
		if err := rows.Scan(&c.ID, &c.TaskID, &c.ServiceURL, &c.PathTemplate, &c.Method, &params, &observations, &c.Status, &c.Reason, &c.AssetID); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(params, &c.Params); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(observations, &c.Observations); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
