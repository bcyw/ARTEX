package db

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Natural keys normalize asset identity within this repository.

func DomainKey(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
}

// RootDomain returns the registrable domain (eTLD+1) for a host and whether the
// host itself IS that apex (§3.1). Edge cases (§3.1 边界处理): an IP literal or a
// host publicsuffix can't classify (localhost / internal / non-ICANN TLD) is
// returned unchanged as its own root with isApex=true — best-effort, never treated
// as a subdomain.
func RootDomain(host string) (root string, isApex bool) {
	h := DomainKey(host)
	if h == "" || net.ParseIP(h) != nil {
		return h, true
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil || etld1 == "" {
		return h, true
	}
	return etld1, h == etld1
}

var (
	reNumeric = regexp.MustCompile(`^\d+$`)
	reUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHex     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reLong    = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}$`)
	reLetter  = regexp.MustCompile(`[A-Za-z]`)
	reDigit   = regexp.MustCompile(`[0-9]`)
)

// TemplatePath collapses high-cardinality path segments into placeholders so the
// graph is not flooded by instances: /user/123 -> /user/{id}.
func TemplatePath(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	used := make(map[string]bool)
	for _, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			used[s] = true
		}
	}
	for i, s := range segs {
		var name string
		switch {
		case s == "":
			continue
		case reNumeric.MatchString(s):
			name = "id"
		case reUUID.MatchString(s):
			name = "uuid"
		case reHex.MatchString(s):
			name = "hex"
		case reLong.MatchString(s) && reLetter.MatchString(s) && reDigit.MatchString(s):
			name = "token"
		}
		if name != "" {
			placeholder := "{" + name + "}"
			for suffix := 2; used[placeholder]; suffix++ {
				placeholder = "{" + name + strconv.Itoa(suffix) + "}"
			}
			used[placeholder] = true
			segs[i] = placeholder
		}
	}
	return strings.Join(segs, "/")
}

func defaultPort(scheme, p string) int {
	if p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}
