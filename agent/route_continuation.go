package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bcyw/artex/db"
)

const (
	routeDefaultCap         = 6
	routeMaxInformationFree = 3
)

// Route 描述一条技术利用路线（GLOSSARY「技术利用路线」）：入口、技术机制、
// 前置条件与验证路径。全部字段可选、原样落 payload——漏洞结果仍归 vuln_type，
// route 只是路线上下文（ADR-0006：路线与漏洞结果分开）。
type Route struct {
	PriorityBasis string   `json:"priority_basis,omitempty"`
	Family        string   `json:"family"`                  // 技术机制族：deserialization/ssrf/ssti/sqli/组件CVE/文件读写/…
	Component     string   `json:"component"`               // 涉及组件与版本（可选，已知组件时填）
	Entry         string   `json:"entry"`                   // 入口：URL/参数/接口
	Parameter     string   `json:"parameter,omitempty"`     // 相关参数/组件身份；参与稳定路线身份
	Prerequisites []string `json:"prerequisites,omitempty"` // 路线成立所需前置条件
	Hypothesis    string   `json:"hypothesis"`              // 利用假设：为什么认为这条路走得通
	NextStep      string   `json:"next_step"`               // 下一步验证动作
	Tested        []string `json:"tested,omitempty"`        // 已测变体（结构化，用于去重）
	Remaining     []string `json:"remaining,omitempty"`     // 尚未验证的关键假设
	Outcome       string   `json:"outcome,omitempty"`       // 最近结果：progress/negative/blocked/no_interaction/service_unavailable/insufficient_impact/impact
	Reason        string   `json:"reason,omitempty"`        // 结果依据（一行）
}

// RouteState 是一次执行路线在规划侧可恢复的状态。它来自既有意图/事实 payload，
// 不另设存储；ID 由任务、入口、机制族与相关组件/参数决定。
type RouteState struct {
	LatestNodeID    int64
	ID              string
	Family          string
	Entry           string
	Component       string
	Parameter       string
	Prerequisites   []string
	Hypothesis      string
	NextStep        string
	Tested          []string
	Remaining       []string
	Outcome         string
	Reason          string
	Intents         int
	OpenIntents     int
	InformationFree int
	Stopped         bool
	Cap             int
	LastInformation string
	// TypeCapReached is set for routes whose target vuln_type is at the catalog
	// cap. The existing type cap is a hard stop that takes precedence over route
	// continuation; it is computed from the intent/fact ledger, not stored.
	TypeCapReached bool
	// ConsumedBasis is every fact/finding already used to justify a new execution
	// of this intent (created intent or original-intent continuation). Re-submitting
	// one of these cannot be counted as fresh information.
	ConsumedBasis []int64
}

// routeCap reads the operator's route budget. Route caps are runtime policy, not
// a schema field; ARTEX_ROUTE_CAP is read on every planning call so an operator
// can lower the bound without rebuilding. Invalid values fall back to the
// documented six-execution limit.
func routeCap() int {
	routeCapMu.RLock()
	override := RouteCapOverride
	routeCapMu.RUnlock()
	if override != nil {
		if n := override(); n > 0 {
			return n
		}
	}
	return routeDefaultCap
}

func (t *ToolSet) routePriority(it intentItem) (int, error) {
	priority := 5
	if it.Route != nil {
		priority = 3
		basis := it.Route.PriorityBasis
		if strings.TrimSpace(it.Route.Entry) != "" && (basis == "intermediate_evidence" || basis == "controllable_input" || basis == "component_chain") {
			for _, id := range pidList(it.ParentIDs) {
				node, err := t.ts.GetNodeWithSources(id)
				if err == nil && routeEvidenceSignature(node) != "" && t.routeEvidenceMatchesEntry(node, it.Route.Entry) {
					priority = 8
					break
				}
			}
		}
	}
	if it.Priority != nil {
		if *it.Priority < 0 || *it.Priority > 10 {
			return 0, fmt.Errorf("priority 必须在 0-10 范围内")
		}
		if it.Route != nil && *it.Priority != priority && strings.TrimSpace(it.PriorityReason) == "" {
			return 0, fmt.Errorf("调整路线默认优先级 %d 必须提供 priority_reason", priority)
		}
		priority = *it.Priority
	}
	return priority, nil
}

// A model's priority claim must be anchored to the same entry, either directly
// on the fact or through the intent that yielded it. Unrelated evidence cannot
// promote a stack guess just because it was listed as a parent.
func (t *ToolSet) routeEvidenceMatchesEntry(node *db.Node, entry string) bool {
	p, err := payloadMap(node.Payload)
	if err != nil {
		return false
	}
	if r := routeFromPayload(p); r != nil && strings.TrimSpace(r.Entry) != "" {
		return normalizeRouteEntry(r.Entry) == normalizeRouteEntry(entry)
	}
	edges, err := t.ts.EdgesTouching([]int64{node.ID})
	if err != nil {
		return false
	}
	for _, edge := range edges {
		if edge.To != node.ID || edge.Rel != db.RelYields {
			continue
		}
		intent, err := t.ts.GetNodeWithSources(edge.From)
		if err != nil || intent == nil || intent.Kind != db.KindIntent {
			continue
		}
		ip, err := payloadMap(intent.Payload)
		if err != nil {
			continue
		}
		if r := routeFromPayload(ip); r != nil && normalizeRouteEntry(r.Entry) == normalizeRouteEntry(entry) {
			return true
		}
	}
	return false
}

var (
	routeCapMu       sync.RWMutex
	RouteCapOverride func() int
)

// SetRouteCapResolver wires the runtime route budget resolver. Set once by the
// server; tests may swap it. Invalid/zero values keep the documented default.
func SetRouteCapResolver(fn func() int) {
	routeCapMu.Lock()
	RouteCapOverride = fn
	routeCapMu.Unlock()
}

func normalizeRoutePart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeRouteEntry(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
		}
		if port != "" {
			host = net.JoinHostPort(host, port)
		}
		s = strings.ToLower(u.Scheme) + "://" + host + u.EscapedPath()
	}
	return s
}

func routeIdentity(entry, family, component, parameter string) string {
	entry = normalizeRouteEntry(entry)
	if strings.TrimSpace(entry) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		entry, normalizeRoutePart(family), normalizeRoutePart(component), normalizeRoutePart(parameter),
	}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func normalizedRoute(r *Route) *Route {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}

func routeFromPayload(p map[string]any) *Route {
	raw, ok := p["route"]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var r Route
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	if r.Outcome == "" {
		if v, ok := p["outcome"].(string); ok {
			r.Outcome = v
		}
	}
	return &r
}

func addRouteState(states map[string]*RouteState, r *Route) *RouteState {
	if r == nil {
		return nil
	}
	id := routeIdentity(r.Entry, r.Family, r.Component, r.Parameter)
	if id == "" {
		return nil
	}
	st := states[id]
	if st == nil {
		st = &RouteState{ID: id, Family: r.Family, Entry: r.Entry, Component: r.Component, Parameter: r.Parameter}
		states[id] = st
	}
	// The route identity owns these fields; later spellings must not rewrite the
	// canonical entry/family/component/parameter used for restore and display.
	st.Prerequisites = appendUnique(st.Prerequisites, r.Prerequisites...)
	st.Tested = appendUnique(st.Tested, r.Tested...)
	st.Remaining = appendUnique(st.Remaining, r.Remaining...)
	st.Remaining = removeTestedHypotheses(st.Remaining, st.Tested)
	if strings.TrimSpace(r.Hypothesis) != "" {
		st.Hypothesis = r.Hypothesis
	}
	if strings.TrimSpace(r.NextStep) != "" {
		st.NextStep = r.NextStep
	}
	if r.Outcome != "" {
		st.Outcome, st.Reason = r.Outcome, r.Reason
	} else if r.Reason != "" {
		st.Reason = r.Reason
	}
	return st
}

// RemainingHypotheses returns the hypotheses/next steps not yet listed as
// tested. The route state keeps the full payload; this is for prompt-safe
// display so a tested variant does not linger as "remaining".
func (st *RouteState) RemainingHypotheses() []string {
	if st == nil {
		return nil
	}
	return removeTestedHypotheses(append([]string(nil), st.Remaining...), st.Tested)
}

func removeTestedHypotheses(remaining, tested []string) []string {
	if len(remaining) == 0 || len(tested) == 0 {
		return remaining
	}
	done := make(map[string]bool, len(tested))
	for _, v := range tested {
		done[normalizeRoutePart(v)] = true
	}
	out := remaining[:0]
	for _, v := range remaining {
		if done[normalizeRoutePart(v)] {
			continue
		}
		out = append(out, v)
	}
	return out
}

func routeSchema() map[string]any {
	return map[string]any{
		"type":        "object",
		"description": "技术利用路线（可选，单条意图一条路线；批量时放各元素内）。family/entry 与关键 component/parameter 共同决定稳定身份：同一路线改 summary、payload 或换意图 id 不会重置预算。",
		"properties": map[string]any{
			"priority_basis": str("优先级依据：intermediate_evidence / controllable_input / component_chain / stack_guess。前三项须以 parent_ids 中的实际证据锚定同一真实入口（事实 route.entry 或产生它的意图 route.entry），否则按低优先级处理。"),
			"family":         str("技术机制族（开放词表：deserialization/ssrf/ssti/sqli/组件CVE/文件读写/命令执行等）"),
			"component":      str("涉及组件与版本；未知/自定义代码可写 custom:<名称>"),
			"entry":          str("真实入口 URL/参数/接口"),
			"parameter":      str("相关参数或组件身份（可选，但同一入口下有多个参数时应填）"),
			"prerequisites":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "路线成立所需的前置条件（可选，逐条可证伪）"},
			"hypothesis":     str("利用假设：为什么认为这条路走得通"),
			"next_step":      str("下一步具体验证动作"),
			"tested":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "已测变体（结构化，用于避免重复 payload）"},
			"remaining":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "尚未验证的关键假设/变体"},
			"outcome":        str("最近结果（可选）：progress/negative/blocked/no_interaction/service_unavailable/observation_incomplete/insufficient_impact/prerequisite_disproved/variants_exhausted/impact。结论性结果请同时写成 fact（带 route 与 outcome），供续探预算读取。"),
			"reason":         str("结果依据（一行，可选）"),
		},
	}
}

func routeExcerpt(s string) string {
	r := []rune(s)
	if len(r) > 240 {
		return string(r[:240]) + "…"
	}
	return s
}

func routeExcerpts(items []string) []string {
	if len(items) > 6 {
		items = items[len(items)-6:]
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = routeExcerpt(s)
	}
	return out
}

func routeStateSummary(st *RouteState) map[string]any {
	remaining := st.RemainingHypotheses()
	return map[string]any{
		"latest_node_id":   st.LatestNodeID,
		"id":               st.ID,
		"family":           routeExcerpt(st.Family),
		"entry":            routeExcerpt(st.Entry),
		"component":        routeExcerpt(st.Component),
		"parameter":        routeExcerpt(st.Parameter),
		"prerequisites":    routeExcerpts(st.Prerequisites),
		"hypothesis":       routeExcerpt(st.Hypothesis),
		"next_step":        routeExcerpt(st.NextStep),
		"tested":           routeExcerpts(st.Tested),
		"tested_total":     len(st.Tested),
		"remaining":        routeExcerpts(remaining),
		"remaining_total":  len(remaining),
		"outcome":          st.Outcome,
		"reason":           routeExcerpt(st.Reason),
		"intents":          st.Intents,
		"open_intents":     st.OpenIntents,
		"information_free": st.InformationFree,
		"stopped":          st.Stopped,
		"cap":              st.Cap,
		"type_cap_reached": st.TypeCapReached,
	}
}

func appendUnique(dst []string, vals ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, v := range dst {
		seen[normalizeRoutePart(v)] = true
	}
	for _, v := range vals {
		k := normalizeRoutePart(v)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		dst = append(dst, v)
	}
	return dst
}

func appendUniqueInts(dst []int64, vals ...int64) []int64 {
	seen := make(map[int64]bool, len(dst))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range vals {
		if v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		dst = append(dst, v)
	}
	return dst
}

func (t *ToolSet) routeStates() map[string]*RouteState {
	states := map[string]*RouteState{}
	if t == nil || t.ts == nil {
		return states
	}
	// A fact with a substantive route outcome (progress, a converged negative,
	// a new blocker, etc.) is structured information about this route even when
	// the planner did not enumerate a new tested variant. Empty windows and OOB
	// service failures are observations about the harness, not route progress.
	information := map[string][]string{}
	typeByRoute := map[string]string{}
	runs, _ := t.ts.IntentRunCounts()
	nodes, err := t.ts.ListByKind(db.KindIntent, 10000)
	if err != nil {
		return states
	}
	// ListByKind is newest-first. Replay oldest-first so the summary reports the
	// last observed hypothesis/next_step instead of letting the oldest intent win.
	for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	for _, n := range nodes {
		p, err := payloadMap(n.Payload)
		if err != nil {
			continue
		}
		route := routeFromPayload(p)
		st := addRouteState(states, route)
		if st == nil {
			continue
		}
		st.LatestNodeID = max(st.LatestNodeID, n.ID)
		if n.State != db.StateIntentDeleted {
			// Each visible intent counts once (it will or did run), and a rerun of
			// that same intent adds its extra completed runs. This keeps the budget
			// honest when the planner continues the original intent instead of
			// creating a new one.
			executions := runs[n.ID]
			if recorded := payloadRouteRuns(p); recorded > executions {
				executions = recorded
			}
			if executions < 1 {
				executions = 1
			}
			st.Intents += executions
			if n.State == "open" || n.State == "running" {
				st.OpenIntents++
			}
		}
		if route != nil {
			information[st.ID] = append(information[st.ID], routeInformation(route))
		}
		if cap := payloadRouteCap(p); cap > 0 {
			st.Cap = cap
		}
		st.ConsumedBasis = appendUniqueInts(st.ConsumedBasis, payloadRouteConsumed(p)...)
		if vt, _ := p["vuln_type"].(string); strings.TrimSpace(vt) != "" {
			typeByRoute[st.ID] = vt
		}
	}
	facts, _ := t.ts.ListByKind(db.KindFact, 10000)
	// Route identity is carried by facts even when a worker omits it from the
	// fact payload: inherit the parent intent's route at read time. This keeps a
	// route's stop state recoverable from the intent/fact graph alone.
	factRoutes := map[int64]*Route{}
	for _, n := range facts {
		p, err := payloadMap(n.Payload)
		if err != nil {
			continue
		}
		if r := routeFromPayload(p); r != nil {
			// A partial route such as {"outcome":"impact"} carries no identity.
			// Leave it unset so the yields edge below inherits the parent intent's
			// full route; otherwise a bare impact fact would never stop the route.
			if routeIdentity(r.Entry, r.Family, r.Component, r.Parameter) != "" {
				factRoutes[n.ID] = r
			}
		}
	}
	if edges, err := t.ts.Edges(5000); err == nil {
		for _, e := range edges {
			if e.Rel != db.RelYields {
				continue
			}
			if r := factRoutes[e.To]; r != nil {
				continue
			}
			intent, err := t.ts.GetNode(e.From)
			if err != nil || intent == nil || intent.Kind != db.KindIntent {
				continue
			}
			ip, err := payloadMap(intent.Payload)
			if err != nil {
				continue
			}
			r := routeFromPayload(ip)
			if r == nil {
				continue
			}
			factRoutes[e.To] = r
		}
	}
	// ListByKind is newest-first. Replay oldest-first so the summary reports the
	// last observed outcome, while information remains a cumulative set.
	for i, j := 0, len(facts)-1; i < j; i, j = i+1, j-1 {
		facts[i], facts[j] = facts[j], facts[i]
	}
	for _, n := range facts {
		p, err := payloadMap(n.Payload)
		if err != nil {
			continue
		}
		r := routeForFact(p, factRoutes[n.ID])
		st := addRouteState(states, r)
		if st == nil {
			continue
		}
		st.LatestNodeID = max(st.LatestNodeID, n.ID)
		confirmed := !isInferredFact(p)
		if r != nil && normalizeRoutePart(r.Outcome) == "negative" {
			confidence, _ := p["confidence"].(string)
			evidence, _ := p["evidence"].(string)
			confirmed = strings.EqualFold(strings.TrimSpace(confidence), "observed") && strings.TrimSpace(evidence) != ""
		}
		if r != nil && routeStopOutcome(r.Outcome) && confirmed {
			st.Stopped = true
		}
		if r != nil {
			information[st.ID] = append(information[st.ID], routeInformation(r))
			if signature := routeEvidenceSignature(n); signature != "" {
				information[st.ID] = append(information[st.ID], "evidence:"+signature)
			}
			if substantiveRouteOutcome(r.Outcome) {
				// A substantive fact is information; the exact node id is not.
				// Repeating the same outcome in a new fact must not reset the
				// three-round no-information counter.
				information[st.ID] = append(information[st.ID], "outcome:"+normalizeRoutePart(r.Outcome))
			}
		}
	}
	for _, st := range states {
		st.LastInformation = mergeRouteInformation(information[st.ID]...)
		if vt := typeByRoute[st.ID]; vt != "" {
			if _, _, reached := t.srcClassCapReached(vt); reached {
				st.TypeCapReached = true
				st.Stopped = true
				st.Outcome = "type_cap_reached"
				st.Reason = fmt.Sprintf("漏洞类型「%s」已达同类上限，路线不再续探", vt)
			}
		}
	}
	t.applyRouteInformationRounds(states)
	return states
}

// routeForFact merges a fact's optional route block with the route inherited
// from the yielding intent. A partial block such as {"outcome":"impact"} keeps
// the parent's identity but must not lose its own outcome.
func routeForFact(p map[string]any, inherited *Route) *Route {
	own := routeFromPayload(p)
	if own == nil {
		own = &Route{}
		own.Outcome, _ = p["outcome"].(string)
	}
	if routeIdentity(own.Entry, own.Family, own.Component, own.Parameter) != "" {
		return own
	}
	if inherited == nil {
		if own.Outcome == "" {
			return nil
		}
		return own
	}
	out := *inherited
	if strings.TrimSpace(own.Entry) != "" {
		out.Entry = own.Entry
	}
	if strings.TrimSpace(own.Family) != "" {
		out.Family = own.Family
	}
	if strings.TrimSpace(own.Component) != "" {
		out.Component = own.Component
	}
	if strings.TrimSpace(own.Parameter) != "" {
		out.Parameter = own.Parameter
	}
	if len(own.Prerequisites) > 0 {
		out.Prerequisites = appendUnique(nil, own.Prerequisites...)
	}
	if len(own.Tested) > 0 {
		out.Tested = appendUnique(out.Tested, own.Tested...)
	}
	if len(own.Remaining) > 0 {
		out.Remaining = appendUnique(out.Remaining, own.Remaining...)
	}
	if strings.TrimSpace(own.Hypothesis) != "" {
		out.Hypothesis = own.Hypothesis
	}
	if strings.TrimSpace(own.NextStep) != "" {
		out.NextStep = own.NextStep
	}
	if own.Outcome != "" {
		out.Outcome = own.Outcome
	}
	if own.Reason != "" {
		out.Reason = own.Reason
	}
	return &out
}

func nodeByID(nodes []*db.Node, id int64) *db.Node {
	for _, n := range nodes {
		if n != nil && n.ID == id {
			return n
		}
	}
	return nil
}

func (t *ToolSet) applyRouteInformationRounds(states map[string]*RouteState) {
	if len(states) == 0 {
		return
	}
	taskID, _ := t.ts.TaskID()
	if taskID <= 0 {
		taskID = t.taskID
	}
	if taskID <= 0 {
		return
	}
	task, _ := t.ts.DB().GetTask(taskID)
	if task != nil && (task.Paused || db.IsTerminal(task.Status)) {
		for _, st := range states {
			st.Stopped = true
			st.Outcome = routeOutcomeGlobalControl
			st.Reason = "任务已暂停或处于终态，路线不再续探"
		}
		return
	}
	if task != nil && task.DeadlineAt != nil && !task.DeadlineAt.After(time.Now()) {
		for _, st := range states {
			st.Stopped = true
			st.Outcome = routeOutcomeGlobalControl
			st.Reason = "任务已到达截止时间，路线不再续探"
		}
		return
	}
	current := map[string]string{}
	for id, st := range states {
		current[id] = st.LastInformation
	}
	rounds, _ := t.ts.RouteRounds(3)
	for id, st := range states {
		streak := 0
		for _, previous := range rounds {
			prev, seen := previous[id]
			if !seen || prev != current[id] {
				break
			}
			streak++
		}
		st.InformationFree = streak
	}
}

func (t *ToolSet) recordRouteRound() error {
	if t == nil || t.ts == nil {
		return nil
	}
	states := t.routeStates()
	values := make(map[string]string, len(states))
	for id, st := range states {
		values[id] = st.LastInformation
	}
	if err := t.ts.RecordRouteRound(values); err != nil {
		return err
	}
	return nil
}

func routeInformation(r *Route) string {
	if r == nil {
		return ""
	}
	parts := make([]string, 0, len(r.Tested)+1)
	for _, tested := range r.Tested {
		if k := normalizeRoutePart(tested); k != "" {
			parts = append(parts, "tested:"+k)
		}
	}
	// no_interaction and service_unavailable are observations about the OOB
	// service or an empty window, not new information about the target route.
	// Keep them in the fact outcome, but do not let them reset the
	// information-free streak.
	if substantiveRouteOutcome(r.Outcome) {
		parts = append(parts, "outcome:"+normalizeRoutePart(r.Outcome))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// substantiveRouteOutcome excludes harness observations (empty OOB window and
// service outage) from route information gain.
func substantiveRouteOutcome(outcome string) bool {
	switch normalizeRoutePart(outcome) {
	case "", "nointeraction", "serviceunavailable", "observationincomplete":
		return false
	default:
		return true
	}
}

// A confirmed route-level negative closes the route; an inconclusive variant
// belongs in tested with a progress/blocked result instead.
func routeStopOutcome(outcome string) bool {
	switch normalizeRoutePart(outcome) {
	case "negative", strings.ReplaceAll(routeOutcomeImpact, "_", ""),
		strings.ReplaceAll(routeOutcomePrerequisiteDisproved, "_", ""),
		strings.ReplaceAll(routeOutcomeVariantsExhausted, "_", ""):
		return true
	default:
		return false
	}
}

// isInferredFact treats an unconfirmed negative/stop conclusion as a lead, not
// a hard stop. The fact schema documents negative conclusions as often inferred;
// stopping a whole route on an inferred guess contradicts the evidence rule.
func isInferredFact(p map[string]any) bool {
	c, _ := p["confidence"].(string)
	return strings.EqualFold(strings.TrimSpace(c), "inferred")
}

func mergeRouteInformation(parts ...string) string {
	seen := map[string]bool{}
	var merged []string
	for _, part := range parts {
		for _, item := range strings.Split(part, "|") {
			item = strings.TrimSpace(item)
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			merged = append(merged, item)
		}
	}
	sort.Strings(merged)
	return strings.Join(merged, "|")
}

func payloadMap(raw json.RawMessage) (map[string]any, error) {
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("empty payload")
	}
	return p, nil
}

func payloadRouteCap(p map[string]any) int {
	for _, key := range []string{"route_cap", "routeCap"} {
		switch v := p[key].(type) {
		case float64:
			if v > 0 {
				return int(v)
			}
		case json.Number:
			if n, err := v.Int64(); err == nil && n > 0 {
				return int(n)
			}
		case int:
			if v > 0 {
				return v
			}
		case int64:
			if v > 0 {
				return int(v)
			}
		}
	}
	return 0
}

func payloadRouteConsumed(p map[string]any) []int64 {
	raw, ok := p["route_consumed"]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var ids []json.RawMessage
	if json.Unmarshal(b, &ids) != nil {
		return nil
	}
	return pidList(ids)
}

func payloadRouteRuns(p map[string]any) int {
	for _, key := range []string{"route_runs", "routeRuns"} {
		switch v := p[key].(type) {
		case float64:
			if v > 0 {
				return int(v)
			}
		case int:
			if v > 0 {
				return v
			}
		case int64:
			if v > 0 {
				return int(v)
			}
		}
	}
	return 0
}

const (
	routeOutcomeImpact                = "impact"
	routeOutcomePrerequisiteDisproved = "prerequisite_disproved"
	routeOutcomeVariantsExhausted     = "variants_exhausted"
	routeOutcomeGlobalControl         = "global_control"
)

func (t *ToolSet) routeContinuation(st *RouteState, it intentItem) error {
	// Components and parameter positions distinguish route hypotheses, but may
	// not multiply the shared entry/mechanism execution budget.
	if it.Route != nil {
		count, cap := 0, 0
		for _, candidate := range t.routeStates() {
			if normalizeRouteEntry(candidate.Entry) == normalizeRouteEntry(it.Route.Entry) && normalizeRoutePart(candidate.Family) == normalizeRoutePart(it.Route.Family) {
				count += candidate.Intents
				if candidate.Cap > 0 && (cap == 0 || candidate.Cap < cap) {
					cap = candidate.Cap
				}
			}
		}
		if it.RouteCap > 0 && (cap == 0 || it.RouteCap < cap) {
			cap = it.RouteCap
		}
		if cap == 0 {
			cap = routeCap()
		}
		if count >= cap {
			return fmt.Errorf("入口/机制路线已执行 %d/%d 次，达到共享上限", count, cap)
		}
	}
	if st == nil {
		return nil
	}
	if st.Cap <= 0 && st.Intents == 0 && it.RouteCap > 0 {
		st.Cap = it.RouteCap
	}
	if st.Cap <= 0 {
		st.Cap = routeCap()
	}
	cap := st.Cap
	if st.TypeCapReached {
		return fmt.Errorf("路线 %s 的目标漏洞类型已达同类上限：既有类型上限优先，不再续探该路线；请改用 record_fact 记录观察或转向其他未触顶类型", st.ID)
	}
	if st.Stopped {
		return fmt.Errorf("路线 %s 已确定停止（%s）：不要继续派意图；请记录新的独立机制或换方向", st.ID, firstNonEmpty(st.Reason, st.Outcome))
	}
	if st.Intents >= cap {
		return fmt.Errorf("路线 %s 已执行 %d/%d 次，达到上限：不要再换 summary/payload 重试；请换入口/机制，或把新增证据记成 fact 交给规划者", st.ID, st.Intents, cap)
	}
	if st.Intents > 0 {
		parentIDs := pidList(it.ParentIDs)
		hasNewTested := hasUnseenRouteValues(it.Route.Tested, st.Tested)
		if st.InformationFree >= routeMaxInformationFree && len(parentIDs) == 0 && !hasNewTested {
			return fmt.Errorf("路线 %s 连续 %d 轮没有新增事实/发现或新 tested 变体：必须换方向，不能再派同路线意图", st.ID, st.InformationFree)
		}
		if len(parentIDs) == 0 && !hasNewTested {
			return fmt.Errorf("路线 %s 已有执行记录，新增意图必须带 parent_ids（此前未用于该路线的新增 fact/finding）或尚未出现过的 tested 变体；换 summary/next_step/机制拼写/意图 id 不算信息增量", st.ID)
		}
		// A continuation must be backed by a fact that is not already the basis of
		// an earlier attempt. The parent set is the planner's structured claim of
		// information gain; free text does not reset the route budget.
		parents := map[int64]bool{}
		evidence := map[int64]*db.Node{}
		for _, kind := range []string{db.KindFact, db.KindFinding} {
			nodes, err := t.ts.ListByKind(kind, 10000)
			if err != nil {
				continue
			}
			for _, n := range nodes {
				evidence[n.ID] = n
			}
		}
		nodes, _ := t.ts.ListByKind(db.KindIntent, 10000)
		routeIntents := map[int64]bool{}
		for _, n := range nodes {
			var p map[string]any
			if json.Unmarshal(n.Payload, &p) != nil {
				continue
			}
			r := routeFromPayload(p)
			if r == nil || routeIdentity(r.Entry, r.Family, r.Component, r.Parameter) != st.ID {
				continue
			}
			routeIntents[n.ID] = true
			for _, id := range payloadParentIDs(n.Payload) {
				parents[id] = true
			}
			for _, id := range payloadRouteConsumed(p) {
				parents[id] = true
			}
		}
		// New intents persist lineage as derived_from edges, not as payload
		// parent_ids. Read those edges so reusing the same fact for another
		// attempt cannot masquerade as fresh information.
		if edges, err := t.ts.Edges(5000); err == nil {
			for _, e := range edges {
				if e.Rel != db.RelDerivedFrom || !routeIntents[e.From] {
					continue
				}
				parents[e.To] = true
			}
		}
		if len(parentIDs) > 0 {
			consumed := map[string]bool{}
			for id := range parents {
				if signature := routeEvidenceSignature(evidence[id]); signature != "" {
					consumed[signature] = true
				}
			}
			hasNew := false
			for _, id := range parentIDs {
				signature := routeEvidenceSignature(evidence[id])
				if !parents[id] && signature != "" && !consumed[signature] {
					hasNew = true
					break
				}
			}
			if !hasNew {
				return fmt.Errorf("续跑路线 %s 没有新增事实作依据：parent_ids 必须包含此前未用于该路线且带实质信息增量的 fact/finding（no_interaction/service_unavailable 不算）；换措辞不算信息增量", st.ID)
			}
		}
	}
	return nil
}

func (t *ToolSet) checkRouteContinuation(st *RouteState, route *Route, parentIDs []int64, routeCap int) error {
	raw := make([]json.RawMessage, 0, len(parentIDs))
	for _, id := range parentIDs {
		raw = append(raw, json.RawMessage(strconv.FormatInt(id, 10)))
	}
	return t.routeContinuation(st, intentItem{Route: route, ParentIDs: raw, RouteCap: routeCap})
}

func routeEvidenceIsInformative(n *db.Node) bool {
	if n == nil {
		return false
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) != nil {
		return true
	}
	outcome, _ := p["outcome"].(string)
	if r := routeFromPayload(p); r != nil && r.Outcome != "" {
		outcome = r.Outcome
	}
	switch normalizeRoutePart(outcome) {
	case "nointeraction", "serviceunavailable", "observationincomplete":
		return false
	}
	return true
}

// Content, not a fresh node ID, determines evidence gain. Execution bookkeeping
// and route hypotheses are deliberately absent from the fingerprint.
func routeEvidenceSignature(n *db.Node) string {
	if !routeEvidenceIsInformative(n) {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) != nil || isInferredFact(p) {
		return ""
	}
	content := map[string]any{}
	for _, key := range []string{"evidence", "proof"} {
		if value, ok := p[key]; ok && value != nil && value != "" {
			content[key] = value
		}
	}
	if len(content) == 0 {
		return ""
	}
	raw, _ := json.Marshal(content)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func hasUnseenRouteValues(candidate, existing []string) bool {
	seen := map[string]bool{}
	for _, v := range existing {
		seen[normalizeRoutePart(v)] = true
	}
	for _, v := range candidate {
		if k := normalizeRoutePart(v); k != "" && !seen[k] {
			return true
		}
	}
	return false
}

func payloadParentIDs(raw json.RawMessage) []int64 {
	var p struct {
		ParentIDs []json.RawMessage `json:"parent_ids"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil
	}
	return pidList(p.ParentIDs)
}
