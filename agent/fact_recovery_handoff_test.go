package agent

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestWorkerFactIsAvailableToPlannerAfterDatabaseReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "business.sqlite")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("persisted handoff", "resume from saved evidence", nil, 0, 0)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{
		"summary": "inspect route evidence",
		"route": map[string]any{
			"entry": "https://fixture.example.test/import", "family": "deserialization",
			"component": "fixture-parser", "hypothesis": "stored observation changes next action",
			"remaining": []string{"inspect response tail"},
		},
	}, 5, nil, "planner")
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	workerTools := NewToolSet(store, "worker")
	workerTools.SetOwnerNode(intentID)
	result := callRecordFact(t, workerTools.WorkerTools(), `{"summary":"captured parser response contains ROUTE-RECOVERY-MARKER","detail":"response tail includes ROUTE-RECOVERY-MARKER","evidence":"traffic_get page: ROUTE-RECOVERY-MARKER","confidence":"observed"}`)
	if result.IsError {
		d.Close()
		t.Fatalf("worker fact write failed: %s", result.Flatten())
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restoredStore := reopened.Exploration(task.ExplorationID)
	factIDs, err := restoredStore.FactsYielded(intentID)
	if err != nil || len(factIDs) != 1 {
		t.Fatalf("fact/yields not restored after reopen: ids=%v err=%v", factIDs, err)
	}
	fact, err := restoredStore.GetNode(factIDs[0])
	if err != nil || fact == nil || fact.Kind != db.KindFact || !strings.Contains(string(fact.Payload), "ROUTE-RECOVERY-MARKER") {
		t.Fatalf("persisted fact was not readable after reopen: node=%+v err=%v", fact, err)
	}

	provider := &scriptedProvider{}
	provider.add(textTurn("Planner received the saved route observation.")...)
	planner := NewPlanner(provider, "test-model", t.TempDir(), nil, 0, 3)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, restoredStore, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner could not run after database reopen: %v", err)
	}
	var plannerInput strings.Builder
	for _, req := range provider.reqs {
		for _, message := range req.Messages {
			plannerInput.WriteString(message.Text())
		}
	}
	if !strings.Contains(plannerInput.String(), "captured parser response contains ROUTE-RECOVERY-MARKER") || !strings.Contains(plannerInput.String(), "ROUTE-RECOVERY-MARKER") {
		t.Fatalf("next planning round did not receive the saved observation: %s", plannerInput.String())
	}
	var routePayload map[string]any
	if err := json.Unmarshal((func() []byte { n, _ := restoredStore.GetNode(intentID); return n.Payload })(), &routePayload); err != nil || routePayload["route"] == nil {
		t.Fatalf("route state was not persisted: payload=%+v err=%v", routePayload, err)
	}
}
