package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

// compliantFindingReport 是十节骨架的合规样例。结构来自实测合规报告(finding 2):
// 必需章节标题行逐字为 ## 漏洞名称 / ## 漏洞复现步骤（POC） / ## 漏洞危害 / ## 修复建议,
// 测试账号节按提示词规则(不依赖登录态)整节省略。
const compliantFindingReport = "# api.example.com 订单接口越权读取漏洞\n\n" +
	"## 漏洞名称\napi.example.com 存在订单接口越权致批量读取他人订单漏洞。\n\n" +
	"## 漏洞复现步骤（POC）\n**Step 1 — 未授权读取他人订单**\n\n" +
	"`http\nGET /api/orders?uid=1 HTTP/1.1\nHost: api.example.com\n`\n\n" +
	"结果: `{\"code\":0,\"data\":[{\"order_id\":9001}]}`\n\n" +
	"## 漏洞危害\n- 换 uid 可枚举读取任意用户订单(实测 uid=1/2 返回不同订单)。\n\n" +
	"## 修复建议\n1. 订单接口补登录态与归属校验。\n"

// fiveSectionFindingReport 是旧五节结构的坏样例,来自实测坏报告(finding 3):
// 「一、漏洞概述/二、影响与危害/三、复现步骤/四、证据 PoC/五、修复建议」,
// 四个必需章节全部缺失。
const fiveSectionFindingReport = "# 度小满支付帮助中心内容接口未授权访问\n\n" +
	"## 一、漏洞概述\n概述正文。\n\n" +
	"## 二、影响与危害\n影响正文。\n\n" +
	"## 三、复现步骤\n步骤正文。\n\n" +
	"## 四、证据 / PoC 汇总\n证据正文。\n\n" +
	"## 五、修复建议\n建议正文。\n"

func TestUpdateFindingReportRejectsMissingSkeleton(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	tools, _, cleanup := agent.AugmentTools(ctx, "reporter", nil)
	defer cleanup()
	res := workflowCall(t, ctx, workflowTool(t, tools, "update_finding_report"),
		map[string]any{"finding_id": f.NodeID, "report": fiveSectionFindingReport}, true)
	for _, h := range []string{"## 漏洞名称", "## 漏洞复现步骤（POC）", "## 漏洞危害", "## 修复建议"} {
		if !strings.Contains(res, h) {
			t.Fatalf("rejection should name missing heading %q: %s", h, res)
		}
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Report != "" {
		t.Fatal("rejected report must not be persisted")
	}
}

func TestUpdateFindingReportAcceptsSkeletonReport(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	tools, _, cleanup := agent.AugmentTools(ctx, "reporter", nil)
	defer cleanup()
	workflowCall(t, ctx, workflowTool(t, tools, "update_finding_report"),
		map[string]any{"finding_id": f.NodeID, "report": compliantFindingReport}, false)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Report != compliantFindingReport {
		t.Fatalf("compliant report not persisted verbatim: %q", finding.Report)
	}
}

func TestUpdateFindingReportRejectsInternalVocabulary(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	tools, _, cleanup := agent.AugmentTools(ctx, "reporter", nil)
	defer cleanup()
	// 实测坏例(finding 4 首轮重写):骨架齐全但正文点名内部工具与过程元数据。
	res := workflowCall(t, ctx, workflowTool(t, tools, "update_finding_report"),
		map[string]any{"finding_id": f.NodeID, "report": compliantFindingReport +
			"\n补充:get_finding_traffic 返回 bindings 为空、version=0,依据 worker#2 的原始请求还原。\n"}, true)
	for _, p := range []string{"get_finding_traffic", "bindings", "worker#"} {
		if !strings.Contains(res, p) {
			t.Fatalf("rejection should name banned phrase %q: %s", p, res)
		}
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if finding.Report != "" {
		t.Fatal("report with internal vocabulary must not be persisted")
	}
}

func TestUpdateFindingReportRejectsOverlongReport(t *testing.T) {
	_, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	tools, _, cleanup := agent.AugmentTools(ctx, "reporter", nil)
	defer cleanup()
	var filler strings.Builder
	for i := 0; i < 350; i++ {
		filler.WriteString("\n填充行")
	}
	res := workflowCall(t, ctx, workflowTool(t, tools, "update_finding_report"),
		map[string]any{"finding_id": f.NodeID, "report": compliantFindingReport + filler.String()}, true)
	if !strings.Contains(res, "行") {
		t.Fatalf("overlong rejection should mention the line cap: %s", res)
	}
}

func TestReporterTriggerMessageSkeletonReminderMigration(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}

	for _, tr := range triggers {
		if tr.OnToolCall && tr.ToolCallMessage == reporterToolCallMessage {
			tr.ToolCallMessage = reporterToolCallMessageV2 // 回拨成旧默认文案
			if err := pg.UpdateTrigger(tr); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	// 一次性 flag 在服务器启动时已消费,按既有迁移测试模式重置后重跑。
	if err := pg.SetSetting("reporter_trigger_budget_discipline_v1", "false"); err != nil {
		t.Fatal(err)
	}
	s.upgradeReporterTriggerMessageV2()
	triggers, err = pg.ListTriggersFor("reporter")
	if err != nil {
		t.Fatal(err)
	}
	migrated := false
	for _, tr := range triggers {
		if !tr.OnToolCall {
			continue
		}
		if tr.ToolCallMessage == reporterToolCallMessageV2 {
			t.Fatal("old default trigger message was not migrated")
		}
		if tr.ToolCallMessage == reporterToolCallMessage {
			migrated = true
		}
	}
	if !migrated {
		t.Fatal("skeleton-reminder trigger message not found after migration")
	}
}
