package db

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Params describe shape and provenance, not raw requests. Only these innocuous
// scalar samples are retained; credentials and arbitrary nested samples stay in
// their evidence store even when an older caller supplies extra JSON fields.
func cleanEndpointParam(in map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range []string{"location", "name", "type", "source", "confidence"} {
		if v, ok := in[key]; ok {
			out[key] = v
		}
	}
	location := strings.ToLower(strings.TrimSpace(fmt.Sprint(in["location"])))
	name, _ := in["name"].(string)
	if location == "header" {
		name = strings.ToLower(name)
	}
	out["location"], out["name"] = location, name
	if evidence := cleanEndpointEvidence(in["evidence"]); len(evidence) > 0 {
		out["evidence"] = evidence
	}
	claims := []any{}
	if old, ok := in["observations"].([]any); ok {
		for _, item := range old {
			if claim, ok := item.(map[string]any); ok {
				claims = append(claims, endpointParamClaim(claim))
			}
		}
	}
	// Once claims exist, the top-level fields are an aggregate view, not a new
	// observation. Re-emitting that view would invent source/evidence pairings.
	if len(claims) == 0 {
		if claim := endpointParamClaim(out); len(claim) > 0 {
			claims = append(claims, claim)
		}
	}
	if len(claims) > 0 {
		out["observations"] = unionEndpointJSON(claims, nil)
	}
	if location == "query" || location == "body" {
		switch strings.ToLower(name) {
		case "page", "limit", "offset", "per_page", "page_size":
			switch v := in["value"].(type) {
			case json.Number, float64, int, int64:
				out["value"] = v
			case string:
				if len(v) <= 10 && reNumeric.MatchString(v) {
					out["value"] = v
				}
			}
		}
	}
	return out
}

func endpointParamClaim(in map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range []string{"type", "source", "confidence"} {
		if v, ok := in[key]; ok {
			out[key] = v
		}
	}
	if evidence := cleanEndpointEvidence(in["evidence"]); len(evidence) > 0 {
		out["evidence"] = evidence
	}
	return out
}

func cleanEndpointEvidence(value any) []any {
	items, _ := value.([]any)
	out := []any{}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ref := map[string]any{}
		for _, key := range []string{"artifact_path", "traffic_id", "activity_id", "code_location"} {
			if v, ok := m[key]; ok {
				switch v.(type) {
				case string, json.Number, float64:
					ref[key] = v
				}
			}
		}
		if len(ref) > 0 {
			out = append(out, ref)
		}
	}
	return unionEndpointJSON(out, nil)
}

func unionEndpointJSON(left, right any) []any {
	byKey := map[string]any{}
	for _, value := range []any{left, right} {
		items, _ := value.([]any)
		for _, item := range items {
			raw, _ := json.Marshal(item)
			byKey[string(raw)] = item
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, byKey[key])
	}
	return out
}

func mergeEndpointParam(left, right map[string]any) map[string]any {
	out := cleanEndpointParam(left)
	right = cleanEndpointParam(right)
	for _, key := range []string{"type", "source", "confidence", "value"} {
		if v, ok := right[key]; ok {
			out[key] = v
		}
	}
	out["evidence"] = unionEndpointJSON(out["evidence"], right["evidence"])
	out["observations"] = unionEndpointJSON(out["observations"], right["observations"])
	return out
}

func endpointParamsJSON(params []map[string]any) (string, error) {
	raw, err := marshalJSONArray(params)
	if err != nil {
		return "", err
	}
	merged, err := mergeJSONArray([]driver.Value{"[]", raw}, "params")
	if err != nil {
		return "", err
	}
	return merged.(string), nil
}
