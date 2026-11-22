package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestHighValueRoutePromptAssembly(t *testing.T) {
	old := PromptOverride
	PromptOverride = nil
	t.Cleanup(func() { PromptOverride = old })
	for role, body := range map[string]string{"planner": plannerSystem("goal", "/data", "/data"), "worker": workerSystem("", "", "/data", "/data")} {
		for _, want := range []string{"通用 0day", "源码", "黑盒", "搜索关闭", "非破坏性", "不自动下载或执行", "negative", "普通越权/未授权", "不主动规划仅证明普通访问差异的验证意图", "核心账户接管"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %s", role, want)
			}
		}
		for _, obsolete := range []string{"硬底线（最高优先）", "先看哪些可收类型还空着", "所有绕过手段走完", "按顶部硬底线必须"} {
			if strings.Contains(body, obsolete) {
				t.Errorf("%s retains %s", role, obsolete)
			}
		}
	}
}

func TestHighValueKnowledgeAndStandardSync(t *testing.T) {
	raw, err := os.ReadFile("../standards/src-acceptance.md")
	if err != nil {
		t.Fatal(err)
	}
	// The fallback is deliberately condensed; changed policy paragraphs must agree.
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "探索力气按") || strings.HasPrefix(line, "**访问差异与真实危害**") || strings.HasPrefix(line, "- **有界续探**") || strings.HasPrefix(line, "- **优先级**") {
			if !strings.Contains(strings.ReplaceAll(srcAcceptanceDefault, "**", ""), strings.ReplaceAll(line, "**", "")) {
				t.Errorf("fallback policy differs: %s", line)
			}
		}
	}
	root := "../skills/clown-src"
	for _, file := range []string{"SKILL.md", "知识库/README.md", "知识库/deserialization-test.md", "知识库/ssrf-test.md", "知识库/injection-test.md", "知识库/el-injection-test.md", "知识库/file-upload-test.md", "知识库/path-traversal-lfi-test.md"} {
		body, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "technical-route-research.md") {
			t.Errorf("%s missing shared route guidance", file)
		}
		if strings.Contains(string(body), "有记录 → SSRF 存在") {
			t.Errorf("%s still treats a callback as a complete vulnerability", file)
		}
	}
	guide, err := os.ReadFile(filepath.Join(root, "rules/technical-route-research.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"通用 0day", "搜索关闭", "oob_generate", "oob_poll", "no_interaction", "service_unavailable", "不自动下载或执行", "非破坏性", "negative"} {
		if !strings.Contains(string(guide), want) {
			t.Errorf("shared guide missing %s", want)
		}
	}
}

func TestRouteEvidencePriorityAndReasonedOverride(t *testing.T) {
	tools := intentTypeToolSet(t)
	fact, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "parser input observed", "confidence": "observed", "evidence": "POST /parse -> parser exception", "route": map[string]any{"entry": "https://example.test/parse", "family": "parser"}}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		basis    string
		parent   bool
		override any
		reason   string
		want     int
		fail     bool
	}{
		{basis: "stack_guess", want: 3},
		{basis: "intermediate_evidence", parent: true, want: 8},
		{basis: "controllable_input", parent: true, want: 8},
		{basis: "component_chain", parent: true, want: 8},
		{basis: "intermediate_evidence", want: 3},
		{basis: "stack_guess", override: 10, fail: true},
		{basis: "stack_guess", override: 10, reason: "verified task-specific impact", want: 10},
		{basis: "stack_guess", override: 0, reason: "defer until prerequisites arrive", want: 0},
		{basis: "stack_guess", override: 11, reason: "invalid", fail: true},
	} {
		input := map[string]any{"summary": "route", "route": map[string]any{"entry": "https://example.test/parse", "family": fmt.Sprintf("parser%d", i), "priority_basis": tc.basis}}
		if tc.parent {
			input["parent_ids"] = []int64{fact}
		}
		if tc.override != nil {
			input["priority"] = tc.override
		}
		if tc.reason != "" {
			input["priority_reason"] = tc.reason
		}
		out, failed := callIntent(t, tools, input)
		if failed != tc.fail {
			t.Fatalf("case %d: %s", i, out)
		}
		if failed {
			continue
		}
		node, err := tools.ts.GetNode(parseCreatedIntentID(t, out))
		if err != nil || node.Priority != tc.want {
			t.Fatalf("case %d priority=%v want %d err=%v", i, node, tc.want, err)
		}
		if tc.reason != "" && !strings.Contains(string(node.Payload), tc.reason) {
			t.Fatal(string(node.Payload))
		}
	}
}

func TestRoutePriorityRequiresRelatedEvidence(t *testing.T) {
	for _, entry := range []string{"", "https://other.test/parse", "https://example.test/parse"} {
		t.Run(entry, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			fact, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "observed input", "confidence": "observed", "evidence": "request -> parser exception", "route": map[string]any{"entry": entry}}, 5, "confirmed", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			out, failed := callIntent(t, tools, map[string]any{"summary": "candidate", "parent_ids": []int64{fact}, "route": map[string]any{"entry": "https://example.test/parse", "family": "parser", "priority_basis": "controllable_input"}})
			if failed {
				t.Fatal(out)
			}
			node, err := tools.ts.GetNode(parseCreatedIntentID(t, out))
			want := 3
			if entry == "https://example.test/parse" {
				want = 8
			}
			if err != nil || node.Priority != want {
				t.Fatalf("entry %q: got %v, want %d: %v", entry, node, want, err)
			}
		})
	}
}

func TestRoutePriorityUsesOriginatingIntentEntry(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/parse", "family": "parser"}
	out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route})
	if failed {
		t.Fatal(out)
	}
	intent := parseCreatedIntentID(t, out)
	raw, _ := json.Marshal(map[string]any{"intent_id": intent, "summary": "parser observed", "confidence": "observed", "evidence": "POST /parse -> parser exception"})
	res, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("%v %s", err, res.Flatten())
	}
	var factID int64
	if _, err := fmt.Sscanf(res.Flatten(), "fact recorded: %d", &factID); err != nil {
		t.Fatal(res.Flatten(), err)
	}
	route["priority_basis"] = "intermediate_evidence"
	out, failed = callIntent(t, tools, map[string]any{"summary": "verify parser", "parent_ids": []int64{factID}, "route": route})
	if failed {
		t.Fatal(out)
	}
	node, err := tools.ts.GetNode(parseCreatedIntentID(t, out))
	if err != nil || node.Priority != 8 {
		t.Fatalf("inherited entry lost: %v %v", node, err)
	}
}

func TestRouteNegativeCannotBePromotedForCoverage(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/parse", "family": "parser"}
	out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route})
	if failed {
		t.Fatal(out)
	}
	id := parseCreatedIntentID(t, out)
	raw, _ := json.Marshal(map[string]any{"intent_id": id, "summary": "reliably disproved", "confidence": "observed", "evidence": "controlled negative response", "outcome": "negative"})
	res, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || res.IsError {
		t.Fatalf("%v %s", err, res.Flatten())
	}
	route["tested"] = []string{"coverage retry"}
	out, failed = callIntent(t, tools, map[string]any{"summary": "coverage gap", "route": route, "priority": 10, "priority_reason": "uncovered type"})
	if !failed {
		t.Fatal("negative route revived:", out)
	}
}

func TestRouteUnsubstantiatedNegativeDoesNotStop(t *testing.T) {
	for _, tc := range []struct{ confidence, evidence string }{{"", ""}, {"observed", ""}, {"", "response"}, {"inferred", "response"}} {
		t.Run(tc.confidence+tc.evidence, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": "https://example.test/parse", "family": "parser"}
			out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route})
			if failed {
				t.Fatal(out)
			}
			id := parseCreatedIntentID(t, out)
			raw, _ := json.Marshal(map[string]any{"intent_id": id, "summary": "unsubstantiated", "confidence": tc.confidence, "evidence": tc.evidence, "outcome": "negative"})
			res, err := tools.recordFact().Call(t.Context(), raw, nil)
			if err != nil || res.IsError {
				t.Fatalf("%v %s", err, res.Flatten())
			}
			route["tested"] = []string{"distinct bounded variant"}
			out, failed = callIntent(t, tools, map[string]any{"summary": "next variant", "route": route})
			if failed {
				t.Fatal("unsubstantiated negative stopped route:", out)
			}
		})
	}
}

func TestRouteOverviewBoundedWithDetailRecovery(t *testing.T) {
	tools := intentTypeToolSet(t)
	long := strings.Repeat("证据", 1000)
	variants := make([]string, 30)
	for i := range variants {
		variants[i] = fmt.Sprintf("variant-%d %s", i, long)
	}
	var last int64
	for i := 0; i < 25; i++ {
		out, failed := callIntent(t, tools, map[string]any{"summary": "candidate", "route": map[string]any{"entry": fmt.Sprintf("https://example.test/%d", i), "family": "parser", "tested": variants, "remaining": variants, "reason": long}})
		if failed {
			t.Fatal(out)
		}
		last = parseCreatedIntentID(t, out)
	}
	res, err := tools.graphOverview().Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var overview struct {
		Total  int `json:"routes_total"`
		Routes []struct {
			Latest int64    `json:"latest_node_id"`
			Reason string   `json:"reason"`
			Tested []string `json:"tested"`
			Total  int      `json:"tested_total"`
		} `json:"routes"`
	}
	if err = json.Unmarshal([]byte(res.Flatten()), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Total != 25 || len(overview.Routes) != 20 {
		t.Fatalf("unbounded: total=%d rows=%d", overview.Total, len(overview.Routes))
	}
	for _, r := range overview.Routes {
		if r.Latest == 0 || len([]rune(r.Reason)) > 241 || len(r.Tested) > 6 || r.Total != 30 {
			t.Fatalf("unbounded row: %+v", r)
		}
	}
	raw, _ := json.Marshal(map[string]any{"id": last})
	detail, err := tools.nodeDetail().Call(t.Context(), raw, nil)
	if err != nil || !strings.Contains(detail.Flatten(), long) || !strings.Contains(detail.Flatten(), "variant-29") {
		t.Fatalf("detail lost: %v %s", err, detail.Flatten())
	}
}
