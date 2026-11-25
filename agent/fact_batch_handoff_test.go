package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/db"
)

// Only the provider is scripted: Execute/Plan, tool dispatch and SQLite are real.
// This proves recovery of supplied observations, not a model's ability to gather
// them, choose a follow-up or infer a vulnerability.
func TestWorkerFactBatchIsAvailableToPlannerAfterDatabaseReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "business.sqlite")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("batch handoff", "recover the reconnaissance observations", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	originID, err := store.OriginFactID()
	if err != nil || originID <= 0 {
		t.Fatalf("task origin missing: id=%d err=%v", originID, err)
	}
	const intentSummary = "inspect the saved response and authentication prerequisites"
	intentID := recordFactTestIntent(t, store, intentSummary)
	intent, err := store.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("reconnaissance intent missing: node=%+v err=%v", intent, err)
	}

	observations := strings.Join([]string{
		"status=200; content-type=text/html",
		"server=fixture-nginx; title=fixture inventory",
		"response tail=BATCH-OBSERVATION-TAIL",
	}, "\n")
	wantFacts := []map[string]any{
		{
			"summary":    "fixture reconnaissance combines the saved response observations",
			"detail":     observations,
			"evidence":   "saved local fixture: status=200; title=fixture inventory",
			"confidence": "observed",
			"experiment": map[string]any{
				"question":         "which response properties were present together?",
				"normal_operation": "inspect the saved fixture response",
				"discovery":        "static",
				"execution_state":  "unknown",
				"observation": map[string]any{
					"position": "saved fixture response",
					"window":   "one recorded response",
					"state":    "complete",
					"excerpt":  observations,
				},
			},
		},
		{
			"summary":    "fixture reconnaissance found an expired session prerequisite",
			"detail":     "saved session metadata is expired; authenticated behavior remains untested",
			"evidence":   "local fixture session: valid=false",
			"confidence": "observed",
		},
	}
	workerProvider := &scriptedProvider{}
	workerProvider.add(toolTurn("batch", "record_fact", map[string]any{
		"facts": []any{
			wantFacts[0],
			map[string]any{"summary": "fixture reconnaissance REJECTED-BATCH-OBSERVATION", "intent_id": 0},
			wantFacts[1],
		},
	})...)
	workerProvider.add(textTurn("batch results received")...)
	worker := NewWorker(workerProvider, "test-model", t.TempDir(), nil, 0, 3)
	_, writes, err := worker.Execute(t.Context(), "worker-batch", task.ID, nil, store, intent, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("worker batch failed: %v", err)
	}
	if writes != (WriteCounts{Facts: 2}) {
		t.Fatalf("partial batch must count only its two facts, without findings: %+v", writes)
	}
	var batch recordedFactBatch
	if err := json.Unmarshal([]byte(factBatchToolResult(t, workerProvider.reqs, "batch")), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.IDs) != 3 || batch.IDs[0] <= 0 || batch.IDs[1] != 0 || batch.IDs[2] <= 0 || batch.IDs[0] == batch.IDs[2] {
		t.Fatalf("batch ids must preserve success/failure input positions: %+v", batch)
	}
	if len(batch.Errors) != 1 || !strings.Contains(batch.Errors["1"], "intent_id") {
		t.Fatalf("explicit invalid ownership must report only index 1: %+v", batch)
	}
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restored := reopened.Exploration(task.ExplorationID)
	yielded, err := restored.FactsYielded(intentID)
	if err != nil || len(yielded) != 2 || !slices.Contains(yielded, batch.IDs[0]) || !slices.Contains(yielded, batch.IDs[2]) {
		t.Fatalf("successful facts must recover under their current intent: ids=%v err=%v", yielded, err)
	}
	facts, err := restored.ListByKind(db.KindFact, 10)
	if err != nil || len(facts) != 3 {
		t.Fatalf("only the origin and two successful facts may persist: nodes=%+v err=%v", facts, err)
	}
	for _, fact := range facts {
		if fact.ID != originID && !slices.Contains(yielded, fact.ID) {
			t.Fatalf("failed or unowned batch entry was persisted: %+v", fact)
		}
	}
	if findings, err := restored.ListByKind(db.KindFinding, 10); err != nil || len(findings) != 0 {
		t.Fatalf("reconnaissance must not fabricate a vulnerability: nodes=%+v err=%v", findings, err)
	}

	// A fresh planner/provider has no worker transcript. Inspect actual tool-result
	// blocks by call id, so neither scripted input nor another result can satisfy
	// the list/detail assertions.
	plannerProvider := &scriptedProvider{}
	plannerProvider.add(toolTurn("facts", "list_facts", map[string]any{"q": "fixture reconnaissance"})...)
	plannerProvider.add(toolTurn("intent", "node_detail", map[string]any{"id": intentID})...)
	for i, id := range []int64{batch.IDs[0], batch.IDs[2]} {
		plannerProvider.add(toolTurn(fmt.Sprintf("fact-%d", i), "node_detail", map[string]any{"id": id})...)
	}
	plannerProvider.add(textTurn("persisted observations received")...)
	planner := NewPlanner(plannerProvider, "test-model", t.TempDir(), nil, 0, 6)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, restored, task.Goal, []TriggerEvent{{Kind: "done", IntentID: intentID}}, nil); err != nil {
		t.Fatalf("planner could not recover the batch: %v", err)
	}
	var page struct {
		Facts []struct {
			ID      int64  `json:"id"`
			Summary string `json:"summary"`
		} `json:"facts"`
		Total   int  `json:"total"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(factBatchToolResult(t, plannerProvider.reqs, "facts")), &page); err != nil {
		t.Fatal(err)
	}
	listed := map[int64]string{}
	for _, fact := range page.Facts {
		listed[fact.ID] = fact.Summary
	}
	wantListed := map[int64]string{batch.IDs[0]: wantFacts[0]["summary"].(string), batch.IDs[2]: wantFacts[1]["summary"].(string)}
	if page.Total != 2 || page.HasMore || len(page.Facts) != 2 || !reflect.DeepEqual(listed, wantListed) {
		t.Fatalf("planner list_facts lost or invented batch entries: %+v", page)
	}
	var recoveredIntent db.Node
	if err := json.Unmarshal([]byte(factBatchToolResult(t, plannerProvider.reqs, "intent")), &recoveredIntent); err != nil {
		t.Fatal(err)
	}
	if recoveredIntent.ID != intentID || recoveredIntent.Kind != db.KindIntent || recoveredIntent.State != "done" || string(recoveredIntent.Payload) != string(intent.Payload) {
		t.Fatalf("planner did not recover the original reconnaissance intent: %+v", recoveredIntent)
	}
	for i, id := range []int64{batch.IDs[0], batch.IDs[2]} {
		var node db.Node
		if err := json.Unmarshal([]byte(factBatchToolResult(t, plannerProvider.reqs, fmt.Sprintf("fact-%d", i))), &node); err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(node.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if node.ID != id || node.Kind != db.KindFact || !reflect.DeepEqual(payload, wantFacts[i]) {
			t.Fatalf("planner node_detail lost complete observations for batch index %d: node=%+v payload=%+v", i*2, node, payload)
		}
	}
}

func factBatchToolResult(t *testing.T, requests []llm.CompletionRequest, callID string) string {
	t.Helper()
	for _, request := range requests {
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
					t.Fatalf("tool call %q failed: %s", callID, text.String())
				}
				return text.String()
			}
		}
	}
	t.Fatalf("provider did not receive tool-result for %q", callID)
	return ""
}
