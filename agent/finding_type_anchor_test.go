package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// 上报期类型归属（票 01：意图锚定 / 明确不收类型拒收 / 目录外放行）的入口级
// 测试。seam 与 finding_cap_test.go 相同：report_finding 工具入口 + internal/testdb
// 临时库隔离。

// typeAnchorToolSet 建任务并返回接好探索存储与 taskID 的上报工具集。
func typeAnchorToolSet(t *testing.T) (*ToolSet, *db.DB) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("type anchor", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := NewToolSet(d.Exploration(task.ExplorationID), "fixture")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	return ts, d
}

// anchorIntent 建一条带类型锚定的意图，返回意图 id。
func anchorIntent(t *testing.T, ts *ToolSet, vulnType string) int64 {
	t.Helper()
	payload := map[string]any{"summary": "验证 " + vulnType + " 的存在与影响"}
	if vulnType != "" {
		payload["vuln_type"] = vulnType
	}
	id, err := ts.ts.AddIntent(payload, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// anchorReport 调用 report_finding，返回工具输出全文；成功时同时返回落库行。
func anchorReport(t *testing.T, ts *ToolSet, d *db.DB, body map[string]any) (string, *db.DBFinding) {
	t.Helper()
	if _, ok := body["severity"]; !ok {
		body["severity"] = "medium"
	}
	body["summary"] = "已验证的类型归属产出"
	body["description"] = "功能与根因"
	body["impact"] = "已验证影响"
	body["remediation"] = "修复建议"
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ts.addFinding().Call(t.Context(), json.RawMessage(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.Flatten()
	if !strings.HasPrefix(out, "finding recorded: ") {
		return out, nil
	}
	lines := strings.SplitN(out, "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("成功输出缺少 JSON 行: %s", out)
	}
	var recorded db.RecordedFinding
	if err := json.Unmarshal([]byte(lines[1]), &recorded); err != nil {
		t.Fatal(err)
	}
	f, err := d.GetFinding(recorded.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if f == nil {
		t.Fatalf("finding %d 未落库", recorded.FindingID)
	}
	return out, f
}

// TestReportFindingTypeAnchoredToIntent 规则①：意图带 vuln_type 时，空
// vulnclass 取意图类型；别名写法折叠后与意图一致即通过；不一致拒收并
// 引导补强/记录事实。
func TestReportFindingTypeAnchoredToIntent(t *testing.T) {
	ts, d := typeAnchorToolSet(t)
	intentID := anchorIntent(t, ts, "注入类")

	// 空 vulnclass → 取意图类型。
	if got, f := anchorReport(t, ts, d, map[string]any{"intent_id": intentID}); f == nil || f.VulnClass != "注入类" {
		t.Fatalf("空 vulnclass 未取意图类型: %s", got)
	}
	// 别名写法（SQLi → 注入类）与意图同桶 → 通过且落库为规范名。
	if got, f := anchorReport(t, ts, d, map[string]any{"intent_id": intentID, "vulnclass": "SQLi"}); f == nil || f.VulnClass != "注入类" {
		t.Fatalf("别名写法未折叠为规范名: %s", got)
	}
	// 与意图不同桶 → 拒收，文案含两个类型名与引导。
	got, f := anchorReport(t, ts, d, map[string]any{"intent_id": intentID, "vulnclass": "越权"})
	if f != nil {
		t.Fatalf("类型不一致的上报未被拒收: %s", got)
	}
	for _, want := range []string{"类型归属不符", "注入类", "越权", "补强已有 finding", "注出一条真实数据"} {
		if !strings.Contains(got, want) {
			t.Fatalf("拒收文案缺少要素 %q: %s", want, got)
		}
	}
}

func TestReportFindingWorkerIntentCannotBeBypassed(t *testing.T) {
	ts, d := typeAnchorToolSet(t)
	intentID := anchorIntent(t, ts, "注入类")
	reconID := anchorIntent(t, ts, "")
	ts.SetOwnerNode(intentID)
	for _, body := range []map[string]any{
		{"vulnclass": "越权"},
		{"intent_id": reconID, "vulnclass": "越权"},
	} {
		if got, f := anchorReport(t, ts, d, body); f != nil {
			t.Fatalf("worker 绕过了当前意图的类型约束: %s", got)
		}
	}
	if got, f := anchorReport(t, ts, d, map[string]any{}); f == nil || f.VulnClass != "注入类" {
		t.Fatalf("worker 省略 intent_id 未继承当前意图类型: %s", got)
	}
}

// TestReportFindingUncollectedTypeRejected 规则②：collect: false 的明确不收
// 类型（无论有无意图锚定）一律拒收，并引用目录里的 stop 文案。
func TestReportFindingUncollectedTypeRejected(t *testing.T) {
	ts, d := typeAnchorToolSet(t)

	// 无意图：直接上报明确不收类型。
	got, f := anchorReport(t, ts, d, map[string]any{"vulnclass": "短信轰炸与无频控发码"})
	if f != nil {
		t.Fatalf("明确不收类型未被拒收: %s", got)
	}
	for _, want := range []string{"不在 SRC 收取范围", "record_fact"} {
		if !strings.Contains(got, want) {
			t.Fatalf("拒收文案缺少要素 %q: %s", want, got)
		}
	}
	// 别名写法同样拒收（折叠后命中 collect: false 条目）。
	if got, f := anchorReport(t, ts, d, map[string]any{"vulnclass": "仅凭状态码"}); f != nil {
		t.Fatalf("明确不收类型的别名写法未被拒收: %s", got)
	}
	// 意图锚定的不收类型：即使与意图一致也拒收（范围规则优先）。
	intentID := anchorIntent(t, ts, "端口指纹版本披露")
	if got, f := anchorReport(t, ts, d, map[string]any{"intent_id": intentID}); f != nil {
		t.Fatalf("意图锚定的明确不收类型未被拒收: %s", got)
	}
}

// TestReportFindingUnknownTypeAllowed 规则③：目录外的新写法放行（词表不堵死
// 新类型），落库保留原写法、状态为 pending（不再产生 quarantined）。
func TestReportFindingUnknownTypeAllowed(t *testing.T) {
	ts, d := typeAnchorToolSet(t)
	got, f := anchorReport(t, ts, d, map[string]any{"vulnclass": "GraphQL 滥用"})
	if f == nil {
		t.Fatalf("目录外类型被误拒: %s", got)
	}
	if f.VulnClass != "GraphQL 滥用" {
		t.Fatalf("目录外类型落库 = %q, want 原写法", f.VulnClass)
	}
	if f.Status != db.FindingPending {
		t.Fatalf("新 finding 状态 = %q, want %q", f.Status, db.FindingPending)
	}
}

// TestReportFindingCanonicalTypeSharesCap 规范名落库后与同类上限闸协同：别名
// 写法归入同一桶；触顶影响探索，不单独拒绝已有证据。
func TestReportFindingCanonicalTypeSharesCap(t *testing.T) {
	ts, d := typeAnchorToolSet(t)
	for i, vc := range []string{"SQL 注入", "sqli", "sql_injection"} {
		if got, f := anchorReport(t, ts, d, map[string]any{"vulnclass": vc}); f == nil {
			t.Fatalf("第 %d 条别名写法被误拒: %s", i+1, got)
		}
	}
	got, f := anchorReport(t, ts, d, map[string]any{"vulnclass": "SQLInjection", "evidence": "fixture: 第四个独立查询拼接路径的正常对照与真实数据结果"})
	if f == nil || f.VulnClass != "注入类" {
		t.Fatalf("触顶后独立证据未沿规范类型保存: %s", got)
	}
	if !strings.Contains(got, "同类上限") {
		t.Fatalf("触顶文案缺少引导: %s", got)
	}
}
