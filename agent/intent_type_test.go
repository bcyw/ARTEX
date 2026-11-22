package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 规划期意图类型化（票 02）的入口级测试：通过 add_intent 工具入口
// 验证 payload，使用 internal/testdb 临时库与临时标准目录，不接触 data/。
// 测试类型与证明物是独立夹具，避免从生产解析/筛选结果反推期望。

// intentTypeToolSet 建任务并返回接好探索存储与 taskID 的规划工具集。
func intentTypeToolSet(t *testing.T) *ToolSet {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src-acceptance.md")
	if err := os.WriteFile(path, []byte(`~~~types
type: 测试甲类
collect: yes
aliases: alpha_test
proof: 甲类最小证明物
type: 测试拒收类
collect: no
aliases: blocked_test
proof: 拒收类证明物
stop: 只有观察没有真实影响
type: 测试乙类
collect: yes
proof: 乙类最小证明物
~~~
`), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	t.Cleanup(func() { SrcAcceptancePath("") })
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("intent type", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := NewToolSet(d.Exploration(task.ExplorationID), "fixture")
	ts.SetTaskID(task.ID)
	return ts
}

// callIntent 调 add_intent，返回输出全文与错误结果标记。
func callIntent(t *testing.T, ts *ToolSet, body map[string]any) (string, bool) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ts.addIntent().Call(t.Context(), json.RawMessage(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Flatten(), res.IsError
}

// parseCreatedIntentID 从单条成功输出 "intent created: N" 取意图 id。
func parseCreatedIntentID(t *testing.T, out string) int64 {
	t.Helper()
	var id int64
	if _, err := fmt.Sscanf(out, "intent created: %d", &id); err != nil {
		t.Fatalf("add_intent 未返回意图 id: %s", out)
	}
	return id
}

// intentPayload 读出意图节点 payload。
func intentPayload(t *testing.T, ts *ToolSet, id int64) map[string]any {
	t.Helper()
	n, err := ts.ts.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("读取意图 %d 节点失败: %v", id, err)
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAddIntentCollectableType 目录内 collect: true 且带类型 → 建意图成功，
// payload 落规范名，proof 缺省取目录证明物。
func TestAddIntentCollectableType(t *testing.T) {
	ts := intentTypeToolSet(t)
	entry := srcTypeEntry{Name: "测试甲类", Proof: "甲类最小证明物"}

	out, isErr := callIntent(t, ts, map[string]any{"summary": "验证 " + entry.Name, "vuln_type": entry.Name})
	if isErr {
		t.Fatalf("可收类型被误拒: %s", out)
	}
	p := intentPayload(t, ts, parseCreatedIntentID(t, out))
	if got := p["vuln_type"]; got != entry.Name {
		t.Fatalf("payload vuln_type = %v, want 规范名 %q", got, entry.Name)
	}
	if got := p["proof"]; got != entry.Proof {
		t.Fatalf("payload proof = %v, want 目录 proof %q", got, entry.Proof)
	}
}

// TestAddIntentAliasFoldsToCanonical 别名写法 → payload 存规范名，不存别名原文。
func TestAddIntentAliasFoldsToCanonical(t *testing.T) {
	ts := intentTypeToolSet(t)
	const alias = " ALPHA-TEST "
	const canonical = "测试甲类"

	out, isErr := callIntent(t, ts, map[string]any{"summary": "验证别名写法", "vuln_type": alias})
	if isErr {
		t.Fatalf("别名写法被误拒: %s", out)
	}
	p := intentPayload(t, ts, parseCreatedIntentID(t, out))
	if got := p["vuln_type"]; got != canonical {
		t.Fatalf("payload vuln_type = %v, want 规范名 %q（别名 %q 应折叠）", got, canonical, alias)
	}
}

// TestAddIntentExplicitProofWins 调用方显式 proof 优先，不被目录 proof 覆盖。
func TestAddIntentExplicitProofWins(t *testing.T) {
	ts := intentTypeToolSet(t)
	entry := srcTypeEntry{Name: "测试甲类"}
	const want = "本方向自定义证明物：拿到真实回显"

	out, isErr := callIntent(t, ts, map[string]any{"summary": "验证自定义证明物", "vuln_type": entry.Name, "proof": want})
	if isErr {
		t.Fatalf("带显式 proof 的可收类型被误拒: %s", out)
	}
	p := intentPayload(t, ts, parseCreatedIntentID(t, out))
	if got := p["proof"]; got != want {
		t.Fatalf("payload proof = %v, want 调用方显式值 %q", got, want)
	}
}

// TestAddIntentReconWithoutType 空 vuln_type = 纯侦察意图，放行且 payload 不带
// vuln_type / proof 键。
func TestAddIntentReconWithoutType(t *testing.T) {
	ts := intentTypeToolSet(t)
	out, isErr := callIntent(t, ts, map[string]any{"summary": "纯侦察：摸清资产面与入口", "proof": "无类型时忽略"})
	if isErr {
		t.Fatalf("侦察意图被误拒: %s", out)
	}
	p := intentPayload(t, ts, parseCreatedIntentID(t, out))
	if _, ok := p["vuln_type"]; ok {
		t.Fatalf("侦察意图 payload 不应带 vuln_type: %#v", p)
	}
	if _, ok := p["proof"]; ok {
		t.Fatalf("侦察意图 payload 不应带 proof: %#v", p)
	}
}

// TestAddIntentUncollectedTypeRejected collect: false → 拒建，错误引用该条 stop。
func TestAddIntentUncollectedTypeRejected(t *testing.T) {
	ts := intentTypeToolSet(t)
	entry := srcTypeEntry{Name: "测试拒收类", Stop: "只有观察没有真实影响"}

	out, isErr := callIntent(t, ts, map[string]any{"summary": "验证明确不收类型", "vuln_type": entry.Name})
	if !isErr {
		t.Fatalf("明确不收类型未被拒建: %s", out)
	}
	for _, want := range []string{entry.Name, entry.Stop, "record_fact"} {
		if !strings.Contains(out, want) {
			t.Fatalf("拒建文案缺少要素 %q: %s", want, out)
		}
	}
}

// TestAddIntentUnknownTypeRejected 目录外自造类型 → 拒建，错误按目录序列出
// 当前可收类型，并提示记 fact / 热改目录。
func TestAddIntentUnknownTypeRejected(t *testing.T) {
	ts := intentTypeToolSet(t)
	names := []string{"测试甲类", "测试乙类"}

	out, isErr := callIntent(t, ts, map[string]any{"summary": "自造类型方向", "vuln_type": "zzz-未收录-自造方向"})
	if !isErr {
		t.Fatalf("目录外类型未被拒建: %s", out)
	}
	for _, want := range []string{"record_fact", "维护者", "热改"} {
		if !strings.Contains(out, want) {
			t.Fatalf("拒建文案缺少引导 %q: %s", want, out)
		}
	}
	if strings.Contains(out, "测试拒收类") {
		t.Fatalf("可收替代列表不应包含拒收类型: %s", out)
	}
	// 每个可收规范名都要出现在文案里，且保持目录书写序。
	last := -1
	for _, name := range names {
		idx := strings.Index(out, name)
		if idx < 0 {
			t.Fatalf("拒建文案缺少可收类型 %q: %s", name, out)
		}
		if idx <= last {
			t.Fatalf("可收类型未按目录序排列（%q 位置 %d <= %d）: %s", name, idx, last, out)
		}
		last = idx
	}
}

// TestAddIntentBatchPerItemRule 批量数组逐条套用同一校验：合法项建成、
// 非法项只进 errors，不影响其他项。
func TestAddIntentBatchPerItemRule(t *testing.T) {
	ts := intentTypeToolSet(t)
	entry := srcTypeEntry{Name: "测试甲类", Proof: "甲类最小证明物"}

	out, isErr := callIntent(t, ts, map[string]any{"intents": []map[string]any{
		{"summary": "批量合法项", "vuln_type": "ALPHA_TEST", "proof": "  "},
		{"summary": "批量非法项", "vuln_type": "zzz-未收录-自造方向"},
		{"summary": "批量侦察项", "vuln_type": "  ", "proof": "无类型时忽略"},
		{"summary": "批量拒收项", "vuln_type": "BLOCKED_TEST"},
		{"summary": "批量覆盖证明物", "vuln_type": entry.Name, "proof": "批量自定义证明物"},
	}})
	if isErr {
		t.Fatalf("批量提交整体被误判为错误: %s", out)
	}
	var res struct {
		IDs    []int64           `json:"ids"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("批量输出不是 JSON: %s", out)
	}
	if len(res.IDs) != 5 {
		t.Fatalf("ids 长度 = %d, want 5（与 intents 等长同序）: %s", len(res.IDs), out)
	}
	if res.IDs[0] <= 0 || res.IDs[2] <= 0 || res.IDs[4] <= 0 {
		t.Fatalf("合法项未建成: %s", out)
	}
	if res.IDs[1] != 0 || res.IDs[3] != 0 || len(res.Errors) != 2 {
		t.Fatalf("未知与拒收类型应逐条失败: %s", out)
	}
	if !strings.Contains(res.Errors["1"], "record_fact") || !strings.Contains(res.Errors["3"], "只有观察没有真实影响") {
		t.Fatalf("批量错误未返回各项的可操作提示: %s", out)
	}
	p := intentPayload(t, ts, res.IDs[0])
	if p["vuln_type"] != entry.Name || p["proof"] != entry.Proof {
		t.Fatalf("批量别名应落规范名和默认证明物: %#v", p)
	}
	p = intentPayload(t, ts, res.IDs[2])
	if _, ok := p["vuln_type"]; ok {
		t.Fatalf("批量侦察项不应带类型: %#v", p)
	}
	if _, ok := p["proof"]; ok {
		t.Fatalf("批量侦察项不应带证明物: %#v", p)
	}
	p = intentPayload(t, ts, res.IDs[4])
	if p["proof"] != "批量自定义证明物" {
		t.Fatalf("批量显式证明物被覆盖: %#v", p)
	}
}

// TestAddIntentCatalogWithoutProofKeepsPayloadContract 类型目录允许 proof 缺省，
// 带类型的意图仍写入 proof 键，区别于不带类型的纯侦察意图。
func TestAddIntentCatalogWithoutProofKeepsPayloadContract(t *testing.T) {
	ts := intentTypeToolSet(t)
	path := filepath.Join(t.TempDir(), "src-acceptance.md")
	if err := os.WriteFile(path, []byte("~~~types\ntype: 测试甲类\ncollect: yes\naliases: custom_alpha\n~~~\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	t.Cleanup(func() { SrcAcceptancePath("") })

	out, isErr := callIntent(t, ts, map[string]any{"summary": "验证自定义目录", "vuln_type": "CUSTOM_ALPHA"})
	if isErr {
		t.Fatalf("自定义可收类型被拒: %s", out)
	}
	p := intentPayload(t, ts, parseCreatedIntentID(t, out))
	if p["vuln_type"] != "测试甲类" {
		t.Fatalf("payload 未采用自定义目录规范名: %#v", p)
	}
	if proof, ok := p["proof"]; !ok || proof != "" {
		t.Fatalf("带类型的 payload 应有目录默认 proof（空串）: %#v", p)
	}
}

// TestAddIntentToolDescriptionTypeDriven 工具描述与参数说明改为类型驱动，
// 不再有「开放的探索方向，不是固定类型」旧口径。
func TestAddIntentToolDescriptionTypeDriven(t *testing.T) {
	ts := intentTypeToolSet(t)
	tool := ts.addIntent()
	desc := tool.Description()
	for _, bad := range []string{"不是固定类型", "开放的探索方向"} {
		if strings.Contains(desc, bad) {
			t.Fatalf("工具描述仍含旧口径 %q: %s", bad, desc)
		}
	}
	for _, want := range []string{"vuln_type", "proof"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("工具描述缺少 %q: %s", want, desc)
		}
	}
	schema, _ := json.Marshal(tool.InputSchema())
	if !strings.Contains(string(schema), "vuln_type") || !strings.Contains(string(schema), "proof") {
		t.Fatalf("参数说明缺少 vuln_type/proof: %s", schema)
	}
}
