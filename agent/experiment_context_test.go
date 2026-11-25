package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordFactPersistsOptionalExperimentContext(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "recover experiment")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := `{"summary":"parser experiment planned","experiment":{"question":"does the parser consume the supplied payload?","normal_operation":"GET /import?url=fixture","identity":"authenticated fixture user","variables":["payload=fixture"],"actions":[{"state":"planned","description":"submit the captured request"}],"observation":{"position":"response body","window":"same request","state":"incomplete"},"execution_state":"planned","conclusion":"controlled input still needs verification","blocker":"","references":[{"kind":"traffic","id":"browser-fixture","excerpt":"response tail"}]}}`
	result := callRecordFact(t, worker.WorkerTools(), input)
	if result.IsError {
		t.Fatalf("record_fact rejected experiment context: %s", result.Flatten())
	}
	ids, err := store.FactsYielded(intentID)
	if err != nil || len(ids) != 1 {
		t.Fatalf("fact was not linked to intent: ids=%v err=%v", ids, err)
	}
	node, err := store.GetNode(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(node.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	experiment, ok := payload["experiment"].(map[string]any)
	if !ok || experiment["execution_state"] != "planned" || !strings.Contains(experiment["conclusion"].(string), "controlled input") {
		t.Fatalf("experiment context was not retained: %+v", payload)
	}
	observation, ok := experiment["observation"].(map[string]any)
	if !ok || observation["state"] != "incomplete" || observation["position"] != "response body" {
		t.Fatalf("observation context was not retained: %+v", experiment)
	}
}

func TestRecordFactRejectsUnknownExperimentState(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "validate experiment state")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	result := callRecordFact(t, worker.WorkerTools(), `{"summary":"invalid state","experiment":{"execution_state":"invented"}}`)
	if !result.IsError || !strings.Contains(result.Flatten(), "execution_state") {
		t.Fatalf("unknown execution state should be rejected: %s", result.Flatten())
	}
}
