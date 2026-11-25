package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/agent"
	"github.com/bcyw/artex/db"
)

func TestReporterRejectionPreservesEvidenceSourceRules(t *testing.T) {
	_, f, _ := trafficEvidenceServer(t)
	tools, _, cleanup := agent.AugmentTools(t.Context(), "reporter", nil)
	defer cleanup()
	result := workflowCall(t, t.Context(), workflowTool(t, tools, "update_finding_report"),
		map[string]any{"finding_id": f.NodeID, "report": compliantFindingReport + "\nget_finding_traffic 返回空清单。\n"}, true)
	for _, unsafe := range []string{"例如「未绑定", "依据执行记录中的原始请求还原"} {
		if strings.Contains(result, unsafe) {
			t.Fatalf("report correction encourages process placeholders or invented raw packets: %s", result)
		}
	}
	for _, required := range []string{"已有 PoC", "证据快照", "不拼造"} {
		if !strings.Contains(result, required) {
			t.Fatalf("report correction lost source rule %q: %s", required, result)
		}
	}
}

// This is a handoff fixture, not a vulnerability or model-quality evaluation.
// The scripted provider only registers known, previously retained command
// material; the Worker, finding storage, Reporter tools and HTTP reads are real.
func TestReporterRecoversCompleteReproductionHandoff(t *testing.T) {
	s, initial, request := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(initial.FindingID)
	if err != nil || finding == nil || finding.TaskID == nil {
		t.Fatal("fixture task unavailable", err)
	}
	taskID := *finding.TaskID
	task := s.m.ResolveTask(fmt.Sprint(taskID))
	wasBinding := s.m.pg.GetBool(settingAgentTrafficBinding, false)
	t.Cleanup(func() { s.m.pg.SetBool(settingAgentTrafficBinding, wasBinding) })
	if err := s.m.pg.SetBool(settingAgentTrafficBinding, false); err != nil {
		t.Fatal(err)
	}
	intentID, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "交接已留存的非 HTTP 复现材料"}, 1, "running", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := task.Store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}

	var material strings.Builder
	material.WriteString("Step 1 — 身份与正常基线\n使用隔离测试账号 alice（提交者）与 bob（审核者），分别建立会话。\n以 alice 执行 queuectl submit baseline.txt，任务 B-17；bob 审核后只产生正常文本 baseline-ok。\n\nStep 2 — 保存待审核文档\n以 alice 执行 queuectl submit crafted.txt，返回任务 Q-42、状态 saved；此时尚未触发处理。\n文档的完整复现配置如下：\n")
	for i := 1; i <= 28; i++ {
		fmt.Fprintf(&material, "input_%02d=preserve-exact-value-%02d; 原始配置逐项保留，后续复验沿用同一文档和会话，不省略输入顺序。\n", i, i)
	}
	material.WriteString("\nStep 3 — 稍后触发\nbob 在保存后的下一审核轮执行 queuectl approve Q-42，处理位置为审核队列；不要重新提交文档。\n\nStep 4 — 独立位置观察\n在 2026-11-25T10:00:00Z 至 10:00:10Z 窗口读取 result/Q-42.txt。\n结果：DELAYED-OBSERVATION-Q42，处理后标记只有在审核触发之后出现。\n影响限于该隔离文档；正常基线 B-17 未产生该标记。")
	poc := material.String()
	beforeTrigger, _, _ := strings.Cut(poc, "Step 3")
	if len([]rune(beforeTrigger)) <= 1500 || strings.Count(poc, "\n") <= 20 {
		t.Fatal("fixture must put the delayed trigger beyond the ordinary preview")
	}
	input, err := json.Marshal(map[string]any{
		"vulnclass": "TEST", "name": "延迟文档处理复现", "severity": "low",
		"summary": "隔离文档审核后的标记输出", "evidence": poc,
		"description": "审核队列处理保存文档时未隔离输入，产生测试标记。", "impact": "隔离文档 Q-42 的处理输出包含测试标记。",
		"remediation": "审核处理前校验文档字段并隔离处理权限。", "session": "alice 提交、bob 审核；两个隔离测试账号。",
	})
	if err != nil {
		t.Fatal(err)
	}
	var recorded db.RecordedFinding
	turn := 0
	provider := retestProvider{complete: func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		turn++
		if turn == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "handoff", Name: "report_finding", Input: input}}}, "tool_use", llm.Usage{}, nil
		}
		for _, message := range req.Messages {
			for _, block := range message.Content {
				if block.Type != llm.BlockToolResult || block.ToolUseID != "handoff" {
					continue
				}
				var result strings.Builder
				for _, part := range block.Content {
					result.WriteString(part.Text)
				}
				_, raw, ok := strings.Cut(result.String(), "\n")
				if block.IsError || !ok || json.Unmarshal([]byte(raw), &recorded) != nil {
					return llm.Message{}, "", llm.Usage{}, fmt.Errorf("report_finding failed: %s", result.String())
				}
			}
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("已登记留存材料")}}, "end_turn", llm.Usage{}, nil
	}}
	worker := agent.NewWorker(provider, "test", t.TempDir(), nil, 100000, 4)
	worker.SetNonStreaming(func() bool { return true })
	worker.SetFindingRecorder(s.evidenceStore())
	if _, writes, err := worker.Execute(t.Context(), "worker", taskID, nil, task.Store, intent, nil, nil, nil, nil); err != nil || writes.Findings != 1 || recorded.NodeID == 0 {
		t.Fatalf("Worker did not register the material: writes=%+v recorded=%+v err=%v", writes, recorded, err)
	}

	ctx := agent.WithRunInfo(t.Context(), agent.RunInfo{TaskID: taskID})
	tools, _, cleanup := agent.AugmentTools(ctx, "reporter", nil)
	defer cleanup()
	preview := workflowCall(t, ctx, workflowTool(t, tools, "list_task_findings"), map[string]any{"task_id": task.ID}, false)
	if strings.Contains(preview, "DELAYED-OBSERVATION-Q42") {
		t.Fatal("fixture should require the full read rather than a compact list")
	}
	detailTool := workflowTool(t, tools, "get_task_node_detail")
	detail := workflowCall(t, ctx, detailTool, map[string]any{"task_id": task.ID, "id": recorded.NodeID}, false)
	var node struct {
		FindingID int64 `json:"finding_id"`
		Payload   struct {
			Evidence struct {
				PoC string `json:"poc"`
			} `json:"evidence"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(detail), &node); err != nil || node.FindingID != recorded.FindingID || node.Payload.Evidence.PoC != poc {
		t.Fatalf("Reporter full read lost material or identity: %s (%v)", detail, err)
	}
	traffic := workflowCall(t, ctx, workflowTool(t, tools, "get_finding_traffic"), map[string]any{"finding_id": node.FindingID}, false)
	var evidence db.FindingTraffic
	if err := json.Unmarshal([]byte(traffic), &evidence); err != nil || len(evidence.Bindings) != 0 {
		t.Fatalf("unbound fixture unexpectedly has raw traffic: %s (%v)", traffic, err)
	}
	// Construct the submitted PoC from the Reporter tool result, never from the
	// original variable: this catches preview loss between registration and read.
	draft := "## 漏洞名称\n延迟文档处理复现\n\n## 测试账号与会话上下文\nalice 提交、bob 审核；两个隔离测试账号。\n\n## 漏洞复现步骤（POC）\n" + node.Payload.Evidence.PoC + "\n\n## 漏洞危害\n隔离文档 Q-42 的处理输出包含测试标记。\n\n## 修复建议\n审核处理前校验文档字段并隔离处理权限。\n"
	workflowCall(t, ctx, workflowTool(t, tools, "update_finding_report"), map[string]any{"finding_id": recorded.NodeID, "report": draft, "evidence_version": evidence.Version}, false)
	readReport := func() string {
		t.Helper()
		response := request("GET", fmt.Sprintf("/api/exploration/findings/%d", recorded.FindingID), "")
		var saved struct {
			Report string `json:"report"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &saved); response.Code != 200 || err != nil {
			t.Fatalf("read submitted report: %d %s (%v)", response.Code, response.Body, err)
		}
		return saved.Report
	}
	if got := readReport(); got != draft {
		t.Fatalf("submission lost reproduction material: %q", got)
	}

	other, err := s.m.CreateTask("unrelated report context", "no source relation", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(other.ID, DeleteTaskOptions{}) })
	workflowCall(t, ctx, detailTool, map[string]any{"task_id": other.ID, "id": recorded.NodeID}, true)
	workflowCall(t, ctx, detailTool, map[string]any{"task_id": task.ID, "id": int64(9223372036854775807)}, true)
	if readReport() != draft {
		t.Fatal("unavailable material must not alter the existing submission")
	}
	if response := request("PATCH", fmt.Sprintf("/api/exploration/findings/%d", recorded.FindingID), `{"status":"confirmed"}`); response.Code != 200 {
		t.Fatal(response.Code, response.Body)
	}
	export := request("GET", "/api/report?task="+task.ID, "")
	if export.Code != 200 || !strings.Contains(export.Body.String(), poc) {
		t.Fatalf("deliverable lost unbound PoC: %d %s", export.Code, export.Body)
	}
	for _, forbidden := range []string{"```http", "待补充", "未绑定"} {
		if strings.Contains(export.Body.String(), forbidden) {
			t.Fatalf("unbound non-HTTP deliverable invented %q", forbidden)
		}
	}
}
