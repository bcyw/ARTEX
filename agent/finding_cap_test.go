package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 同类上限闸（票 02：触顶拒收与引导）的入口级测试。
// seam：report_finding 工具入口（模仿 finding_recorder_test.go 的直接
// ts.addFinding().Call 模式），internal/testdb 临时库隔离环境。

// capToolSet 建任务并返回接好 AssetStore/taskID 的上报工具集。
func capToolSet(t *testing.T) (*ToolSet, *db.DB) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("cap gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := NewToolSet(d.Exploration(task.ExplorationID), "fixture")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), d.Companies())
	return ts, d
}

// capReport 上报一条黑名单之外的常规 finding，返回工具输出全文。
func capReport(t *testing.T, ts *ToolSet, vulnclass string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"vulnclass": vulnclass, "severity": "medium", "summary": "已验证的同类型产出",
		"description": "功能与根因", "impact": "已验证影响", "remediation": "修复建议",
	})
	res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Flatten()
}

func TestReportFindingSameClassCap(t *testing.T) {
	ts, _ := capToolSet(t)
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	for i := 0; i < 3; i++ {
		if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
			t.Fatalf("第 %d 条同类 finding 被误拒（默认上限 3）: %s", i+1, got)
		}
	}
	got := capReport(t, ts, "GraphQL 滥用")
	if strings.HasPrefix(got, "finding recorded: ") {
		t.Fatalf("触顶后第 4 条同类 finding 未被拒收: %s", got)
	}
	for _, want := range []string{"同类上限", "补强已有 finding", "record_fact"} {
		if !strings.Contains(got, want) {
			t.Fatalf("拒收文案缺少引导要素 %q: %s", want, got)
		}
	}
	if notices != 3 || ts.writes.Findings != 3 {
		t.Fatalf("触顶拒收不应计入产出或触发通知: notices=%d writes=%d", notices, ts.writes.Findings)
	}
}

func TestReportFindingCapAliasFolding(t *testing.T) {
	ts, _ := capToolSet(t)
	// 折叠表内同一桶的多种写法（SQL 注入 / sqli / sql_injection → 注入类）共占名额。
	for _, vc := range []string{"SQL 注入", "sqli", "sql_injection"} {
		if got := capReport(t, ts, vc); !strings.HasPrefix(got, "finding recorded: ") {
			t.Fatalf("别名写法 %q 被误拒: %s", vc, got)
		}
	}
	if got := capReport(t, ts, "SQLInjection"); !strings.Contains(got, "同类上限") {
		t.Fatalf("别名折叠共占名额未生效（第 4 条折叠写法应触顶拒收）: %s", got)
	}
}

func TestReportFindingUncollectedTypeNotRecorded(t *testing.T) {
	ts, _ := capToolSet(t)
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	// 票 01：旧版「黑名单命中进隔离区」退场，改为目录 collect: no 的明确不收
	// 类型直接拒收（不落库、不占名额、不触发 reporter）。
	for i := 0; i < 3; i++ {
		got := capReport(t, ts, "clickjacking")
		if !strings.Contains(got, "不在 SRC 收取范围") {
			t.Fatalf("第 %d 条明确不收类型未拒收: %s", i+1, got)
		}
	}
	if ts.writes.Findings != 0 || notices != 0 {
		t.Fatalf("拒收的上报不应落库或通知: writes=%d notices=%d", ts.writes.Findings, notices)
	}
	// 同任务内可收类型照常上报，说明拒收未污染上限口径。
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
		t.Fatalf("可收类型被误伤: %s", got)
	}
}

func TestReportFindingCapExcludesInvalidStatus(t *testing.T) {
	ts, d := capToolSet(t)
	var ids []int64
	for i := 0; i < 3; i++ {
		got := capReport(t, ts, "GraphQL 滥用")
		var out db.RecordedFinding
		if err := json.Unmarshal([]byte(strings.SplitN(got, "\n", 2)[1]), &out); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, out.FindingID)
	}
	// 三条全部转入无效状态：false_positive / duplicate / ignored 不计入上限口径。
	for i, st := range []string{db.FindingFalsePositive, db.FindingDuplicate, db.FindingIgnored} {
		if _, err := d.SetFindingStatus(ids[i], st); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
			t.Fatalf("无效状态应释放名额（第 %d 条被误拒）: %s", i+1, got)
		}
	}
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.Contains(got, "同类上限") {
		t.Fatalf("释放名额后重新触顶未拒收: %s", got)
	}
}

func TestReportFindingCapMetaUnavailableNoGate(t *testing.T) {
	// AssetStore 缺席（nil）时无法交叉 findings 表状态：按节点存在宽松计数，
	// 同桶计数仍应触顶；绝不因 meta 不可用而放行无限上报，也不误杀（口径与
	// findingTypeCounts 的回退方向一致：审查修复项 1）。
	ts, _ := capToolSet(t)
	ts.as = nil // 模拟 meta 交叉不可用
	for i := 0; i < 3; i++ {
		if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
			t.Fatalf("meta 不可用时第 %d 条被误拒: %s", i+1, got)
		}
	}
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.Contains(got, "同类上限") {
		t.Fatalf("meta 不可用时同桶计数仍应触顶（按节点存在计）: %s", got)
	}
}

func TestReportFindingCapIndependentClasses(t *testing.T) {
	ts, _ := capToolSet(t)
	for i := 0; i < 3; i++ {
		if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
			t.Fatalf("第 %d 条被误拒: %s", i+1, got)
		}
	}
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.Contains(got, "同类上限") {
		t.Fatalf("触顶未拒收: %s", got)
	}
	// 不同类型各自计数、互不影响：另一类照常可报。
	if got := capReport(t, ts, "缓存投毒"); !strings.HasPrefix(got, "finding recorded: ") {
		t.Fatalf("不同类型被同类上限误伤: %s", got)
	}
}

func TestReportFindingCapHotLoaded(t *testing.T) {
	// 上限值取自热载标准文件的机器可查区：自定义 cap: 1 重启即生效语义
	// （srcAcceptance 每次现读，改文件无需重编译）。
	dir := t.TempDir()
	path := filepath.Join(dir, "src-acceptance.md")
	custom := "测试收取标准\n\n~~~types\ncap: 1\n~~~\n"
	if err := os.WriteFile(path, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	defer SrcAcceptancePath("")
	ts, _ := capToolSet(t)
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.HasPrefix(got, "finding recorded: ") {
		t.Fatalf("热载上限 1 下首条被误拒: %s", got)
	}
	if got := capReport(t, ts, "GraphQL 滥用"); !strings.Contains(got, "同类上限") {
		t.Fatalf("热载上限值未生效（第 2 条应拒收）: %s", got)
	}
}
