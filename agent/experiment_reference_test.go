package agent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestRecordFactValidatesGraphExperimentReferences(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "validate references")
	referenceID, err := store.AddNode(db.KindFact, map[string]any{"summary": "captured baseline"}, 5, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(intentID)
	valid := fmt.Sprintf(`{"summary":"reference is available","experiment":{"execution_state":"executed","references":[{"kind":"node","id":%d,"excerpt":"captured baseline"}]}}`, referenceID)
	if result := callRecordFact(t, worker.WorkerTools(), valid); result.IsError {
		t.Fatalf("existing node reference should be accepted: %s", result.Flatten())
	}
	missing := `{"summary":"reference is missing","experiment":{"execution_state":"executed","references":[{"kind":"node","id":9223372036854775807}]}}`
	if result := callRecordFact(t, worker.WorkerTools(), missing); !result.IsError || !strings.Contains(result.Flatten(), "reference") {
		t.Fatalf("missing node reference should be rejected: %s", result.Flatten())
	}
	unsupported := `{"summary":"reference kind is not trusted","experiment":{"references":[{"kind":"model_claim","id":"anything"}]}}`
	if result := callRecordFact(t, worker.WorkerTools(), unsupported); !result.IsError || !strings.Contains(result.Flatten(), "kind") {
		t.Fatalf("unsupported reference kind should be rejected: %s", result.Flatten())
	}
}
