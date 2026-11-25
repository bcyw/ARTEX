package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// Existing material is useful context, but is not proof that this worker run
// performed an action, completed an observation, or sent an allocated probe.
func TestExperimentRejectsMaterialAsExecution(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "execution provenance")
	nodeID, err := store.AddNode(db.KindFact, map[string]any{"summary": "baseline"}, 5, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := store.AppendActivity(db.Activity{NodeID: &intentID, Kind: "tool_use", Tool: "Bash", ToolUseID: "not-executed", Summary: "planned command"})
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "worker")
	tools.SetOwnerNode(intentID)
	tools.SetReferenceVerifier(func(string, string) (string, bool) { return "globally captured traffic", true })
	for name, experiment := range map[string]string{
		"node":                     fmt.Sprintf(`{"execution_state":"executed","execution_basis":{"kind":"node","id":%d,"verified":true}}`, nodeID),
		"tool use only":            fmt.Sprintf(`{"actions":[{"state":"executed","basis":{"kind":"activity","id":%d,"verified":true}}]}`, activityID),
		"self asserted provenance": fmt.Sprintf(`{"observation":{"state":"complete","basis":{"kind":"node","id":%d,"provenance":{"run_id":"invented","execution":"completed"}}}}`, nodeID),
		"global traffic":           `{"discovery":"executed","execution_basis":{"kind":"traffic","id":"elsewhere","verified":true}}`,
		"allocated probe":          fmt.Sprintf(`{"probe":{"allocated":true,"send_state":"sent","send_basis":{"kind":"node","id":%d,"verified":true}}}`, nodeID),
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"summary": name, "experiment": json.RawMessage(experiment)})
			if result := callRecordFact(t, tools.WorkerTools(), string(body)); !result.IsError {
				t.Fatalf("unexecuted material was accepted as execution: %s", result.Flatten())
			}
		})
	}
}

func TestExperimentClearsForgedProvenanceOnPlannedBasis(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "planned provenance")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := fmt.Sprintf(`{"summary":"plan only","experiment":{"execution_state":"planned","run":{"run_id":"forged"},"execution_basis":{"kind":"node","id":%d,"provenance":{"run_id":"forged"}},"actions":[{"state":"planned","basis":{"kind":"node","id":%d,"run":{"run_id":"forged"}}}],"observation":{"state":"incomplete","basis":{"kind":"node","id":%d,"relation":"forged"}},"probe":{"allocated":true,"send_state":"allocated_only","send_basis":{"kind":"node","id":%d,"source_task_id":"forged"}}}}`, intentID, intentID, intentID, intentID)
	result := callRecordFact(t, worker.WorkerTools(), input)
	if result.IsError {
		t.Fatal(result.Flatten())
	}
	var id int64
	if _, err := fmt.Sscanf(result.Flatten(), "fact recorded: %d", &id); err != nil {
		t.Fatal(err)
	}
	for _, tool := range worker.WorkerTools() {
		if tool.Name() != "node_detail" {
			continue
		}
		input, _ := json.Marshal(map[string]any{"id": id})
		result, err := tool.Call(t.Context(), input, nil)
		if err != nil || result.IsError || strings.Contains(result.Flatten(), "forged") {
			t.Fatalf("self-authored basis provenance survived: %s err=%v", result.Flatten(), err)
		}
		return
	}
	t.Fatal("node_detail not exposed")
}
