package agent

import (
	"strconv"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestExperimentReferencesGainReadableExcerpts(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "reference excerpts")
	referenceID, err := store.AddNode(db.KindFact, map[string]any{"summary": "captured baseline response", "detail": "long detail not copied into excerpt"}, 5, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	activityID, err := store.AppendActivity(db.Activity{NodeID: &intentID, Worker: "worker", Kind: "tool", Tool: "Bash", Summary: "curl -s https://fixture.example.test/import"})
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	input := `{"summary":"references are readable","experiment":{"execution_state":"executed","references":[
		{"kind":"node","id":` + strconv.FormatInt(referenceID, 10) + `},
		{"kind":"activity","id":` + strconv.FormatInt(activityID, 10) + `}
	]}}`
	if result := callRecordFact(t, worker.WorkerTools(), input); result.IsError {
		t.Fatalf("reference write failed: %s", result.Flatten())
	}
	refs := factPayload(t, store, intentID)["experiment"].(map[string]any)["references"].([]any)
	nodeRef := refs[0].(map[string]any)
	if nodeRef["excerpt"] != "captured baseline response" {
		t.Fatalf("node reference excerpt = %v", nodeRef["excerpt"])
	}
	activityRef := refs[1].(map[string]any)
	if !strings.Contains(activityRef["excerpt"].(string), "curl -s") {
		t.Fatalf("activity reference excerpt = %v", activityRef["excerpt"])
	}
}

func TestExperimentTrafficReferencesUseHostVerifier(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "traffic reference")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	known := "browser-fixture"
	worker.SetReferenceVerifier(func(kind, id string) (string, bool) {
		if kind == "traffic" && id == known {
			return "GET /fixture 200 (42 bytes)", true
		}
		return "", false
	})
	valid := `{"summary":"traffic reference verified","experiment":{"references":[{"kind":"traffic","id":"` + known + `"}]}}`
	if result := callRecordFact(t, worker.WorkerTools(), valid); result.IsError {
		t.Fatalf("host-verified traffic reference was rejected: %s", result.Flatten())
	}
	ref := factPayload(t, store, intentID)["experiment"].(map[string]any)["references"].([]any)[0].(map[string]any)
	if ref["verified"] != true || ref["excerpt"] != "GET /fixture 200 (42 bytes)" {
		t.Fatalf("traffic reference was not verified with an excerpt: %+v", ref)
	}
	missing := `{"summary":"traffic reference missing","experiment":{"references":[{"kind":"traffic","id":"absent"}]}}`
	if result := callRecordFact(t, worker.WorkerTools(), missing); !result.IsError || !strings.Contains(result.Flatten(), "reference") {
		t.Fatalf("unverifiable traffic reference should be rejected: %s", result.Flatten())
	}
}
