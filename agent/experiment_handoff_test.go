package agent

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

func factPayload(t *testing.T, store *db.ExplorationStore, intentID int64) map[string]any {
	t.Helper()
	ids, err := store.FactsYielded(intentID)
	if err != nil || len(ids) != 1 {
		t.Fatalf("expected exactly one yielded fact: ids=%v err=%v", ids, err)
	}
	node, err := store.GetNode(ids[0])
	if err != nil || node == nil {
		t.Fatalf("fact %d unreadable: %v", ids[0], err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestRecordFactCarriesMultipleExperiments(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "multiple experiments")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := `{"summary":"two distinguishable experiments","experiments":[
		{"question":"normal operation baseline","execution_state":"executed","observation":{"state":"complete","position":"response body"}},
		{"question":"delayed trigger","execution_state":"planned","observation":{"state":"incomplete"}}
	]}`
	if result := callRecordFact(t, worker.WorkerTools(), input); result.IsError {
		t.Fatalf("record_fact rejected multiple experiments: %s", result.Flatten())
	}
	payload := factPayload(t, store, intentID)
	experiments, ok := payload["experiments"].([]any)
	if !ok || len(experiments) != 2 {
		t.Fatalf("experiments were not retained as a list: %+v", payload)
	}
	second := experiments[1].(map[string]any)
	if second["execution_state"] != "planned" || second["observation"].(map[string]any)["state"] != "incomplete" {
		t.Fatalf("second experiment lost its planned/incomplete state: %+v", second)
	}
	conflict := `{"summary":"conflicting shape","experiment":{"question":"one"},"experiments":[{"question":"two"}]}`
	if result := callRecordFact(t, worker.WorkerTools(), conflict); !result.IsError || !strings.Contains(result.Flatten(), "experiment") {
		t.Fatalf("experiment and experiments together should be rejected: %s", result.Flatten())
	}
}

func TestRecordFactValidatesExperimentExecutionStates(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "validate experiment states")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	invalid := []string{
		`{"summary":"bad observation","experiment":{"observation":{"state":"finished"}}}`,
		`{"summary":"bad action","experiment":{"actions":[{"state":"sent","description":"x"}]}}`,
		`{"summary":"bad discovery","experiment":{"discovery":"guessed"}}`,
	}
	for _, input := range invalid {
		if result := callRecordFact(t, worker.WorkerTools(), input); !result.IsError {
			t.Fatalf("invalid experiment state was accepted: %s", input)
		}
	}
	valid := `{"summary":"valid experiment states","experiment":{"execution_state":"blocked","discovery":"simulated","actions":[{"state":"blocked","description":"local block"}],"observation":{"state":"incomplete"}}}`
	if result := callRecordFact(t, worker.WorkerTools(), valid); result.IsError {
		t.Fatalf("valid experiment states were rejected: %s", result.Flatten())
	}
}

func TestRecordFactPreservesReconHandoffDistinctions(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "recon handoff")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := `{"summary":"normal operation blocked by expired identity","experiment":{"discovery":"simulated","controllable_input":"url parameter","identity":{"valid":false,"note":"fixture session expired"},"normal_operation":"GET /import?url=fixture","observation":{"position":"proxy traffic","state":"incomplete"},"execution_state":"blocked","blocker":"identity expired before normal request"}}`
	if result := callRecordFact(t, worker.WorkerTools(), input); result.IsError {
		t.Fatalf("recon handoff was rejected: %s", result.Flatten())
	}
	experiment := factPayload(t, store, intentID)["experiment"].(map[string]any)
	if experiment["discovery"] != "simulated" || experiment["controllable_input"] != "url parameter" || experiment["blocker"] != "identity expired before normal request" {
		t.Fatalf("recon distinctions were lost: %+v", experiment)
	}
	if identity := experiment["identity"].(map[string]any); identity["valid"] != false {
		t.Fatalf("invalid identity was not preserved: %+v", identity)
	}
}

func TestRecordFactRequiresBasisBeforeClaimingProbeSent(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "probe send basis")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	activityID, err := store.AppendActivity(db.Activity{NodeID: &intentID, Worker: "worker", Kind: "tool", Tool: "Bash", Summary: "curl fixture"})
	if err != nil {
		t.Fatal(err)
	}

	sentWithoutBasis := `{"summary":"probe sent without proof","experiment":{"probe":{"allocated":true,"send_state":"sent"}}}`
	if result := callRecordFact(t, worker.WorkerTools(), sentWithoutBasis); !result.IsError || !strings.Contains(result.Flatten(), "send_basis") {
		t.Fatalf("claiming a sent probe without a basis should be rejected: %s", result.Flatten())
	}
	withBasis := `{"summary":"probe sent and traceable","experiment":{"probe":{"allocated":true,"send_state":"sent","send_basis":{"kind":"activity","id":` + strconv.FormatInt(activityID, 10) + `}}}}`
	if result := callRecordFact(t, worker.WorkerTools(), withBasis); result.IsError {
		t.Fatalf("probe with a real activity basis was rejected: %s", result.Flatten())
	}
	probe := factPayload(t, store, intentID)["experiment"].(map[string]any)["probe"].(map[string]any)
	if probe["send_state"] != "sent" || probe["send_basis"].(map[string]any)["verified"] != true {
		t.Fatalf("probe send basis was not recorded as verified: %+v", probe)
	}
}

func TestRecordFactKeepsAllocatedOnlyAndBlockedProbesDistinct(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "probe states")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := `{"summary":"probe state distinctions","experiments":[
		{"question":"allocated only","probe":{"allocated":true,"send_state":"allocated_only"}},
		{"question":"script sent, unknown","probe":{"allocated":true,"send_state":"script_unknown"}},
		{"question":"locally blocked","probe":{"allocated":true,"send_state":"blocked"},"execution_state":"blocked"}
	]}`
	if result := callRecordFact(t, worker.WorkerTools(), input); result.IsError {
		t.Fatalf("distinct probe states were rejected: %s", result.Flatten())
	}
	experiments := factPayload(t, store, intentID)["experiments"].([]any)
	want := []string{"allocated_only", "script_unknown", "blocked"}
	for i, state := range want {
		probe := experiments[i].(map[string]any)["probe"].(map[string]any)
		if probe["send_state"] != state {
			t.Fatalf("experiment %d send_state = %v, want %s", i, probe["send_state"], state)
		}
	}
	invalid := `{"summary":"unowned probe","experiment":{"probe":{"allocated":false,"send_state":"sent","send_basis":{"kind":"activity","id":1}}}}`
	if result := callRecordFact(t, worker.WorkerTools(), invalid); !result.IsError || !strings.Contains(result.Flatten(), "allocated") {
		t.Fatalf("sending from a probe that was never allocated should be rejected: %s", result.Flatten())
	}
}
