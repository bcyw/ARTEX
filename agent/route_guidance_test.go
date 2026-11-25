package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
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
	syncStandardsPolicy(t, string(raw), srcAcceptanceDefault)
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

// syncStandardsPolicy pins every machine-enforced policy paragraph of the disk
// standard (standards/src-acceptance.md) to the embedded fallback
// (srcAcceptanceDefault). The fallback prose is deliberately condensed, so the
// check normalizes emphasis/whitespace and probes each policy by a
// representative fragment pair: the disk fragment must exist on disk, and the
// fallback must carry the same policy in its own wording. Add a pair whenever a
// new policy paragraph lands in the standard; keeping this table in the same
// test file as the catalog check makes forgetting it hard.
func syncStandardsPolicy(t *testing.T, disk, fallback string) {
	t.Helper()
	normalize := func(s string) string {
		s = strings.ReplaceAll(s, "**", "")
		s = strings.ReplaceAll(s, " ", "")
		return s
	}
	d, f := normalize(disk), normalize(fallback)
	for _, p := range []struct{ name, diskFrag, fallbackFrag string }{
		{"公开性判据", "完成判据：找到未登录可见的正常前端入口拿到同样数据", "完成判据：找到未登录可见的正常前端入口拿到同样数据"},
		{"密钥例外", "公开性只豁免无危害信息，不豁免可利用凭据", "公开性只豁免无危害信息，不豁免可利用凭据"},
		{"受控证明边界", "真实身份/权限或业务不变量突破才成立", "真实身份/权限或业务不变量突破才成立"},
		{"机制与结果分离", "worker 不得改标签、改指其他 intent_id 或覆盖原 proof 绕过归属", "worker 不得改标签、改指其他 intent_id 或覆盖原 proof 绕过归属"},
		{"硬门-先证伪", "主动跑否定实验", "主动跑否定实验"},
		{"硬门-PoC可复现", "非 HTTP 或未抓包时用命令/日志等可核验证据，不要求流量绑定", "非 HTTP 或未抓包时用命令/日志等可核验证据，不要求流量绑定"},
		{"硬门-链路终局", "终局结果，不是中间信号", "终局结果，不是中间信号"},
		{"查重", "补强已有 finding，不新写", "补强已有 finding，不新写"},
		{"不挖清单", "只允许花 1-2 次请求确认能否升级到链路终局", "只允许花 1-2 次请求确认能否升级到链路终局"},
		{"访问差异", "不主动规划仅证明普通访问差异的验证意图", "不主动规划仅证明普通访问差异的验证意图"},
		{"同类上限", "已经取得、符合收取纪律的独立根因证据仍可登记", "已经取得、符合收取纪律的独立根因证据仍可登记"},
		{"别名折叠", "目录外新写法仍自成一桶、照常计数并允许上报", "目录外新写法仍自成一桶、照常计数并允许上报"},
		{"定级封顶", "评分封顶【中】", "评分封顶【中】"},
		{"复测", "连续无法复现的次数不构成误报证据", "连续无法复现的次数不构成误报证据"},
		{"路线身份", "改变摘要、payload、机制拼写或意图 ID 不重置去重与预算", "改变摘要、payload、机制拼写或意图 ID 不重置去重与预算"},
		{"有界续探", "默认最多创建 6 次执行意图", "默认最多创建 6 次执行意图"},
		{"信息增量", "未执行计划、重复证据、nonce、新 ID 与改写的摘要/结果不算增量", "未执行计划、重复证据、nonce、新 ID 与改写的摘要/结果不算增量"},
		{"无信息换向", "连续 3 个规划轮次同路线没有可核验的新观察时换方向", "连续 3 个规划轮次同路线没有可核验的新观察时换方向"},
		{"OOB解释", "暂无交互或 OOB 服务故障不证明目标无漏洞", "暂无交互或 OOB 服务故障不证明目标无漏洞"},
	} {
		if !strings.Contains(d, normalize(p.diskFrag)) {
			t.Errorf("standard %s: disk fragment not found (update the pair): %s", p.name, p.diskFrag)
		}
		if !strings.Contains(f, normalize(p.fallbackFrag)) {
			t.Errorf("standard %s: fallback policy missing or reworded: %s", p.name, p.fallbackFrag)
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
	factID := routeObservationFact(t, tools, intent, map[string]any{"summary": "parser observed", "confidence": "observed", "evidence": "POST /parse -> parser exception"})
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
	routeObservationFact(t, tools, id, map[string]any{"summary": "reliably disproved", "confidence": "observed", "evidence": "controlled negative response", "outcome": "negative"})
	route["tested"] = []string{"coverage retry"}
	out, failed = callIntent(t, tools, map[string]any{"summary": "coverage gap", "route": route, "priority": 10, "priority_reason": "uncovered type"})
	if !failed || !strings.Contains(out, "已确定停止") {
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
			fresh := routeObservationFact(t, tools, 0, map[string]any{"summary": "new discriminator", "evidence": "POST /parse -> distinct parser handler"})
			out, failed = callIntent(t, tools, map[string]any{"summary": "next variant", "route": route, "parent_ids": []int64{fresh}})
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
