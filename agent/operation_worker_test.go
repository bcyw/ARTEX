package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/db"
)

// The scripted provider checks assembled inputs and real tool handoffs through
// Worker.Execute. It proves engineering behavior, not real-model decisions or
// vulnerability discovery effectiveness.
func TestOperationWorkerBoundsInitialContext(t *testing.T) {
	tools := intentTypeToolSet(t)
	method := strings.Repeat("M", 1024)
	selector := "body:" + strings.Repeat("层", 2048) + ".Value"
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "inspect the assigned operation",
		"route": map[string]any{
			"entry": "https://example.test/import", "family": "parser",
			"method": method, "input_location": selector,
		},
	})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	intent, err := tools.ts.GetNode(parseCreatedIntentID(t, created.Flatten()))
	if err != nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{}
	provider.add(textTurn("operation context inspected; no experiment executed")...)
	taskID, err := tools.ts.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 3)
	if _, _, err := worker.Execute(t.Context(), "operation-worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(provider.reqs) == 0 {
		t.Fatal("worker made no model request")
	}
	initial := provider.reqs[0]
	system := strings.Join(initial.System, "\n")
	assembled := system
	for _, message := range initial.Messages {
		assembled += "\n" + message.Text()
	}
	for field, full := range map[string]string{"method": method, "input_location": selector} {
		if strings.Contains(assembled, full) {
			t.Errorf("initial worker input contains unbounded route.%s (%d runes)", field, len([]rune(full)))
		}
	}
	for _, want := range []string{
		strings.Repeat("M", 240) + "…",
		"body:" + strings.Repeat("层", 235) + "…",
		"截断",
		fmt.Sprintf(`node_detail({"id":%d})`, intent.ID),
	} {
		if !strings.Contains(system, want) {
			t.Errorf("initial worker system omitted bounded operation or retrieval hint %q", want)
		}
	}
}

func TestOperationWorkerRetrievesFullSelectorAndHandsOffFact(t *testing.T) {
	tools := intentTypeToolSet(t)
	selector := "body:" + strings.Repeat("nested.", 512) + "Expression"
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "retrieve the complete assigned selector before handoff",
		"route": map[string]any{
			"entry": "https://example.test/import", "family": "parser",
			"method": "POST", "input_location": selector,
		},
	})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	intent, err := tools.ts.GetNode(parseCreatedIntentID(t, created.Flatten()))
	if err != nil {
		t.Fatal(err)
	}
	originalPayload := string(intent.Payload)
	before := readOperations(t, tools).Routes
	provider := &scriptedProvider{}
	provider.add(toolTurn("assigned-operation", "node_detail", map[string]any{"id": intent.ID})...)
	provider.add(toolTurn("operation-handoff", "record_fact", map[string]any{
		"summary":   "complete operation context handed off; experiment remains planned",
		"intent_id": intent.ID,
		"experiment": map[string]any{
			"method": "POST", "input_location": selector, "execution_state": "planned",
		},
	})...)
	provider.add(textTurn("operation context handed off")...)
	taskID, err := tools.ts.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 4)
	_, writes, err := worker.Execute(t.Context(), "operation-worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if writes.Facts != 1 || len(provider.reqs) != 3 {
		t.Fatalf("want one fact after detail retrieval, writes=%+v requests=%d", writes, len(provider.reqs))
	}
	if strings.Contains(strings.Join(provider.reqs[0].System, "\n"), selector) {
		t.Fatal("initial worker system contains the complete long selector")
	}
	// This is the real node_detail result seen before the scripted record_fact.
	detail := operationWorkerToolResult(t, provider.reqs[1], "assigned-operation")
	if !strings.Contains(detail, selector) {
		t.Fatal("worker node_detail tool result lost the complete selector")
	}
	var recovered db.Node
	if err := json.Unmarshal([]byte(detail), &recovered); err != nil {
		t.Fatal(err)
	}
	if string(recovered.Payload) != originalPayload || string(intent.Payload) != originalPayload {
		t.Fatal("display summarization changed the stored or assigned intent payload")
	}
	var factID int64
	result := operationWorkerToolResult(t, provider.reqs[2], "operation-handoff")
	if _, err := fmt.Sscanf(result, "fact recorded: %d", &factID); err != nil {
		t.Fatalf("record_fact did not return a fact: %q (%v)", result, err)
	}
	fact := operationTool(t, tools.PlannerTools(), "node_detail", map[string]any{"id": factID})
	if fact.IsError || !strings.Contains(fact.Flatten(), selector) {
		t.Fatal("planner cannot recover the complete selector from the worker's fact")
	}
	after := readOperations(t, tools).Routes
	if len(before) != 1 || len(after) != 1 || before[0].ID != after[0].ID {
		t.Fatal("worker retrieval and fact handoff changed the operation identity")
	}
}

func TestOperationWorkerPreservesOrdinaryFieldsAndExplicitProof(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector string
	}{
		{"short operation", "body:user.Id"},
		{"truncated operation", "body:" + strings.Repeat("nested.", 64) + "Id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			summary := "ordinary task summary: " + strings.Repeat("保持原文", 80)
			proof := "explicit proof: " + strings.Repeat("具体证明物", 80)
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
				"summary": summary, "vuln_type": "alpha_test", "proof": proof,
				"route": map[string]any{
					"entry": "https://example.test/import", "family": "parser",
					"method": "POST", "input_location": tc.selector,
				},
			})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			intent, err := tools.ts.GetNode(parseCreatedIntentID(t, created.Flatten()))
			if err != nil {
				t.Fatal(err)
			}
			provider := &scriptedProvider{}
			provider.add(textTurn("standard card inspected; no experiment executed")...)
			taskID, err := tools.ts.TaskID()
			if err != nil {
				t.Fatal(err)
			}
			worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 3)
			if _, _, err := worker.Execute(t.Context(), "operation-worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			if len(provider.reqs) == 0 {
				t.Fatal("worker made no model request")
			}
			system := strings.Join(provider.reqs[0].System, "\n")
			for _, want := range []string{
				summary, `"method":"POST"`,
				"【本方向的漏洞类型】测试甲类",
				"【拿什么才算数（危害最小证明物）】" + proof,
			} {
				if !strings.Contains(system, want) {
					t.Errorf("ordinary field or explicit proof was changed: %q", want)
				}
			}
			if strings.Contains(system, "【拿什么才算数（危害最小证明物）】甲类最小证明物") {
				t.Error("catalog default replaced the explicit proof")
			}
			if tc.name == "short operation" {
				if !strings.Contains(system, string(intent.Payload)) || strings.Contains(system, "【操作字段摘要】") {
					t.Error("short operation no longer preserves the original intent payload verbatim")
				}
			}
		})
	}
}

func operationWorkerToolResult(t *testing.T, request llm.CompletionRequest, callID string) string {
	t.Helper()
	for _, message := range request.Messages {
		for _, block := range message.Content {
			if block.Type != llm.BlockToolResult || block.ToolUseID != callID {
				continue
			}
			var text strings.Builder
			for _, content := range block.Content {
				text.WriteString(content.Text)
			}
			if block.IsError {
				t.Fatalf("tool %s failed: %s", callID, text.String())
			}
			return text.String()
		}
	}
	t.Fatalf("missing tool result for %s", callID)
	return ""
}
