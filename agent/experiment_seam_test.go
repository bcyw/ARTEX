package agent

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/db"
	"github.com/bcyw/artex/traffic"
)

// A worker saves a planned delayed trigger; a later worker recovers the same
// question and preserves an incomplete observation. No actual trigger runs in
// this JSON-context test; TestExperimentRealDelayedHandoff covers real execution.
//
// Scope: the provider is scripted, so this proves the deterministic orchestration
// and that each worker's own assembled input carries the saved experiment (and
// nothing earlier). It does not measure whether a real model would notice,
// follow or correctly conclude from that context — that needs an isolated model
// evaluation with a fixed provider, config and budget.
func TestExperimentHandoffSurvivesNextWorker(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "business.sqlite")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("delayed experiment", "save then observe later", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	workDir := t.TempDir()

	provider := &scriptedProvider{}
	planner := NewPlanner(provider, "test-model", workDir, nil, 0, 3)
	provider.add(toolTurn("i1", "add_intent", map[string]any{"summary": "trigger then observe the delayed import"})...)
	provider.add(textTurn("intent planned")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, store, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner round failed: %v", err)
	}
	intents, err := store.ListByKind(db.KindIntent, 5)
	if err != nil || len(intents) != 1 {
		t.Fatalf("expected one planned intent: %v %v", intents, err)
	}
	intent := intents[0]

	provider.add(toolTurn("save", "record_fact", map[string]any{
		"summary": "delayed trigger saved for later observation",
		"experiment": map[string]any{
			"question":         "does the delayed import job run the supplied expression?",
			"normal_operation": "POST /import with fixture document",
			"execution_state":  "planned",
			"observation":      map[string]any{"position": "scheduled job output", "state": "incomplete"},
		},
	})...)
	provider.add(textTurn("saved")...)
	first := NewWorker(provider, "test-model", workDir, nil, 0, 4)
	if _, _, err := first.Execute(t.Context(), "worker-1", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatalf("first worker failed: %v", err)
	}
	if err := store.SetIntentState(intent.ID, "done"); err != nil {
		t.Fatal(err)
	}

	// A later planning round sees the saved planned experiment and dispatches a
	// follow-up intent referencing that fact.
	factIDs, err := store.FactsYielded(intent.ID)
	if err != nil || len(factIDs) != 1 {
		t.Fatalf("saved experiment fact missing: %v %v", factIDs, err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	store = d.Exploration(task.ExplorationID)
	intent, err = store.GetNode(intent.ID)
	if err != nil {
		t.Fatal(err)
	}
	factIDs, err = store.FactsYielded(intent.ID)
	if err != nil || len(factIDs) != 1 {
		t.Fatalf("planned experiment fact did not survive reopen: %v %v", factIDs, err)
	}
	plannerReqStart := len(provider.reqs)
	provider.add(toolTurn("facts", "list_facts", map[string]any{})...)
	provider.add(toolTurn("detail", "node_detail", map[string]any{"id": factIDs[0]})...)
	provider.add(toolTurn("i2", "add_intent", map[string]any{
		"summary":    "read the delayed import job output",
		"parent_ids": []int64{factIDs[0]},
	})...)
	provider.add(textTurn("follow-up planned")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, store, task.Goal, []TriggerEvent{{Kind: "worker_done", IntentID: intent.ID}}, nil); err != nil {
		t.Fatalf("second planner round failed: %v", err)
	}
	plannerResults := toolResults(provider.reqs[plannerReqStart:])
	for _, want := range []string{`"id":3`, "delayed trigger saved for later observation"} {
		if !strings.Contains(plannerResults, want) {
			t.Fatalf("planner list_facts result omitted %q: %s", want, plannerResults)
		}
	}
	for _, want := range []string{"does the delayed import job run the supplied expression?", "POST /import with fixture document", "planned", "incomplete", "scheduled job output"} {
		if !strings.Contains(plannerResults, want) {
			t.Fatalf("planner node_detail result omitted %q: %s", want, plannerResults)
		}
	}
	all, err := store.ListByKind(db.KindIntent, 10)
	if err != nil || len(all) != 2 {
		t.Fatalf("follow-up intent was not created: %v %v", all, err)
	}
	var followUp *db.Node
	for _, n := range all {
		if n.ID != intent.ID {
			followUp = n
		}
	}
	if followUp == nil {
		t.Fatal("follow-up intent missing")
	}

	workerReqStart := len(provider.reqs)
	provider.add(toolTurn("recover", "node_detail", map[string]any{"id": factIDs[0]})...)
	provider.add(toolTurn("observe", "record_fact", map[string]any{
		"summary": "delayed import observation still needs its real trigger",
		"experiment": map[string]any{
			"question":          "does the delayed import job run the supplied expression?",
			"reference_fact_id": factIDs[0],
			"execution_state":   "unknown",
			"observation":       map[string]any{"position": "scheduled job output", "state": "incomplete"},
			"references":        []any{map[string]any{"kind": "node", "id": factIDs[0]}},
		},
	})...)
	provider.add(textTurn("incomplete observation recovered")...)
	second := NewWorker(provider, "test-model", workDir, nil, 0, 4)
	if _, _, err := second.Execute(t.Context(), "worker-2", task.ID, nil, store, followUp, nil, nil, nil, nil); err != nil {
		t.Fatalf("second worker failed: %v", err)
	}
	recovered := toolResults(provider.reqs[workerReqStart:])
	for _, want := range []string{"does the delayed import job run the supplied expression?", "POST /import with fixture document", "planned", "incomplete", "scheduled job output"} {
		if !strings.Contains(recovered, want) {
			t.Fatalf("second worker did not recover %q from its public fact tool: %s", want, recovered)
		}
	}
	observed, err := store.FactsYielded(followUp.ID)
	if err != nil || len(observed) != 1 {
		t.Fatalf("observation fact missing: %v %v", observed, err)
	}
	node, err := store.GetNode(observed[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	experiment := payload["experiment"].(map[string]any)
	if experiment["execution_state"] != "unknown" || experiment["observation"].(map[string]any)["state"] != "incomplete" {
		t.Fatalf("second worker changed an unexecuted experiment into completion: %+v", experiment)
	}
	if experiment["reference_fact_id"].(float64) != float64(factIDs[0]) {
		t.Fatalf("observation did not cite the saved fact: %+v", experiment)
	}
}

func toolResults(requests []llm.CompletionRequest) string {
	var results string
	for _, request := range requests {
		for _, message := range request.Messages {
			for _, block := range message.Content {
				if block.Type == llm.BlockToolResult {
					for _, content := range block.Content {
						results += content.Text
					}
				}
			}
		}
	}
	return results
}

// Capture off, a non-HTTP tool result, missing traffic material and an invalid
// identity must each stay representable and distinct.
func TestExperimentHandoffDegradedPaths(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("degraded handoff", "capture off paths", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "degraded path"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := store.AppendActivity(db.Activity{NodeID: &intentID, Worker: "worker", Kind: "tool", Tool: "nmap", Summary: "nmap -sV fixture (no HTTP)"})
	if err != nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{}
	provider.add(toolTurn("degraded", "record_fact", map[string]any{
		"summary": "non-HTTP scan result and invalid identity handoff",
		"experiment": map[string]any{
			"discovery":        "static",
			"identity":         map[string]any{"valid": false, "note": "fixture session expired"},
			"normal_operation": "nmap -sV fixture",
			"execution_state":  "blocked",
			"blocker":          "identity expired before the authenticated request",
			"observation":      map[string]any{"position": "tool stdout", "state": "incomplete"},
			"references": []any{
				map[string]any{"kind": "activity", "id": activityID},
				map[string]any{"kind": "traffic", "id": "browser-missing"},
			},
		},
	})...)
	provider.add(textTurn("degraded handoff saved")...)
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 3)
	// No reference verifier: traffic stays unverified instead of being trusted.
	if _, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatalf("degraded worker failed: %v", err)
	}
	payload := factPayload(t, store, intentID)
	experiment := payload["experiment"].(map[string]any)
	if experiment["execution_state"] != "blocked" || !strings.Contains(experiment["blocker"].(string), "identity") {
		t.Fatalf("degraded execution state lost: %+v", experiment)
	}
	if identity := experiment["identity"].(map[string]any); identity["valid"] != false {
		t.Fatalf("invalid identity lost: %+v", identity)
	}
	refs := experiment["references"].([]any)
	activityRef := refs[0].(map[string]any)
	if activityRef["verified"] != true || !strings.Contains(activityRef["excerpt"].(string), "nmap") {
		t.Fatalf("non-HTTP activity reference lost: %+v", activityRef)
	}
	trafficRef := refs[1].(map[string]any)
	if trafficRef["verified"] != false {
		t.Fatalf("unverifiable traffic material must stay unverified: %+v", trafficRef)
	}
}

// A real captured exchange, wired through the host verifier, must round-trip
// from the worker tool to the stored fact.
func TestExperimentHandoffCitesCapturedTraffic(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("traffic citation", "cite captured evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "cite traffic"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	trafficID, err := tr.ImportBrowser(traffic.BrowserExchange{
		URL: "https://fixture.example.test/import", Method: "POST", Status: 200,
		ResponseHeaders: []traffic.ImportHeader{{Name: "Content-Type", Value: "text/plain"}},
		ResponseBody:    "job accepted",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{}
	provider.add(toolTurn("cite", "record_fact", map[string]any{
		"summary": "captured import response cited",
		"experiment": map[string]any{
			"execution_state": "unknown",
			"references":      []any{map[string]any{"kind": "traffic", "id": trafficID}},
		},
	})...)
	provider.add(textTurn("cited")...)
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 3)
	worker.SetReferenceVerifier(func(kind, id string) (string, bool) { return tr.ReferenceExcerpt(id) })
	if _, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatalf("traffic citation worker failed: %v", err)
	}
	ref := factPayload(t, store, intentID)["experiment"].(map[string]any)["references"].([]any)[0].(map[string]any)
	if ref["verified"] != true || !strings.Contains(ref["excerpt"].(string), "POST https://fixture.example.test/import") {
		t.Fatalf("captured traffic reference not verified: %+v", ref)
	}
}
