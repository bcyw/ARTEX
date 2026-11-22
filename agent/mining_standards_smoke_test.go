package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the published planner tools, persisted intent, worker card and finding
// feedback together, using an isolated SQLite DB and an editable catalog.
func TestMiningStandardsEntrySmoke(t *testing.T) {
	ts := intentTypeToolSet(t)
	path := filepath.Join(t.TempDir(), "editable.md")
	if err := os.WriteFile(path, []byte(srcAcceptance()), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	call := func(name string, body map[string]any) (string, bool) {
		t.Helper()
		for _, tool := range ts.PlannerTools() {
			if tool.Name() != name {
				continue
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			res, err := tool.Call(t.Context(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			return res.Flatten(), res.IsError
		}
		t.Fatalf("missing published tool %s", name)
		return "", true
	}
	for _, tool := range ts.PlannerTools() {
		if tool.Name() == "report_finding" {
			raw, err := json.Marshal(tool.InputSchema())
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			for _, key := range schema.Required {
				if key == "vulnclass" {
					t.Fatal("published report_finding schema must allow intent-anchored type omission")
				}
			}
		}
	}
	out, failed := call("add_intent", map[string]any{"summary": "verify fixture", "vuln_type": "alpha_test"})
	if failed {
		t.Fatal(out)
	}
	id := parseCreatedIntentID(t, out)
	node, err := ts.ts.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	card := renderIntentTask(node)
	for _, want := range []string{"测试甲类", "甲类最小证明物", "不得改报其他类型"} {
		if !strings.Contains(card, want) {
			t.Fatalf("worker card missing %q: %s", want, card)
		}
	}
	report := map[string]any{"intent_id": id, "severity": "medium", "summary": "verified", "description": "root cause", "impact": "verified impact", "remediation": "fix", "evidence": "controlled command output"}
	report["vulnclass"] = "测试乙类"
	if out, failed := call("report_finding", report); !failed || !strings.Contains(out, "类型归属不符") {
		t.Fatalf("type switch accepted: %s", out)
	}
	delete(report, "vulnclass")
	if out, failed := call("report_finding", report); failed {
		t.Fatal(out)
	}
	out, failed = call("graph_overview", nil)
	if failed {
		t.Fatal(out)
	}
	var overview map[string]any
	if err := json.Unmarshal([]byte(out), &overview); err != nil {
		t.Fatal(err)
	}
	rows := overview["type_coverage"].([]any)
	var found bool
	for _, row := range rows {
		r := row.(map[string]any)
		if r["type"] == "测试甲类" && r["findings"] == float64(1) {
			found = true
		}
	}
	if !found {
		t.Fatalf("finding missing from coverage: %s", out)
	}
	if strings.Contains(renderWorkerGraphOverview(overview), "type_coverage") {
		t.Fatal("planner coverage leaked to worker")
	}
	if out, failed := call("add_intent", map[string]any{"summary": "blocked", "vuln_type": "blocked_test"}); !failed {
		t.Fatalf("non-collectable intent accepted: %s", out)
	}

	// A same-process edit affects the next entry call, without restart or reseed.
	if err := os.WriteFile(path, []byte("~~~types\ntype: 测试甲类\ncollect: no\nstop: 热改止损线\n~~~\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, failed := call("report_finding", report); !failed || !strings.Contains(out, "热改止损线") {
		t.Fatalf("hot edit ignored: %s", out)
	}
}

func TestMiningStandardsCatalogCopiesAgree(t *testing.T) {
	raw, err := os.ReadFile("../standards/src-acceptance.md")
	if err != nil {
		t.Fatal(err)
	}
	catalogBlock := func(s string) string {
		t.Helper()
		parts := strings.SplitN(s, "~~~types", 2)
		if len(parts) != 2 {
			t.Fatal("missing types block")
		}
		return strings.SplitN(parts[1], "~~~", 2)[0]
	}
	if catalogBlock(string(raw)) != catalogBlock(srcAcceptanceDefault) {
		t.Fatal("standard and embedded catalog differ")
	}
	for name, body := range map[string]string{"file": string(raw), "embedded": srcAcceptanceDefault} {
		for _, want := range []string{"类型目录", "本类标准卡", "type_coverage", "上报类型与意图锚定", "collect: no", "无需重编译或重启"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s standard missing %q", name, want)
			}
		}
		for _, stale := range []string{"黑名单一票否决", "拦截进隔离区", "重启进程即生效", "绝不拒收"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s standard retains %q", name, stale)
			}
		}
	}
}
