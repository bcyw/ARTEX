package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestRouteBudgetSharedAcrossParameters(t *testing.T) {
	tools := intentTypeToolSet(t)
	for i := 0; i < 7; i++ {
		out, failed := callIntent(t, tools, map[string]any{"summary": "variant", "route": map[string]any{
			"entry": "https://example.test/import", "family": "parser", "parameter": fmt.Sprint(i),
		}})
		if failed != (i == 6) {
			t.Fatalf("attempt %d: %s", i+1, out)
		}
	}
}

func TestRouteBudgetConcurrentAdmission(t *testing.T) {
	tools := intentTypeToolSet(t)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, failed := callIntent(t, tools, map[string]any{"summary": "variant", "route": map[string]any{
				"entry": "https://example.test/import", "family": "parser", "parameter": fmt.Sprint(i),
			}})
			if !failed {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 6 {
		t.Fatalf("accepted %d, want 6", accepted.Load())
	}
}

func TestRouteDistinctRealEntrypoints(t *testing.T) {
	tools := intentTypeToolSet(t)
	for _, entry := range []string{"https://example.test/Admin", "https://example.test/admin", "https://www.example.test/admin", "http://example.test/admin"} {
		out, failed := callIntent(t, tools, map[string]any{"summary": "distinct entry", "route": map[string]any{"entry": entry, "family": "parser"}})
		if failed {
			t.Fatal(out)
		}
	}
}

func TestContinueIntentIdentityAndRollback(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/import", "family": "parser"}
	out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route})
	if failed {
		t.Fatal(out)
	}
	id := parseCreatedIntentID(t, out)
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	before, _ := tools.ts.GetNode(id)
	fact, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "observed parser response", "evidence": "parser response: unexpected token at 12", "confidence": "observed"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	tools.SetContinueWork(func(int64, string) error { return fmt.Errorf("queue unavailable") })
	call := func(r map[string]any) string {
		raw, _ := json.Marshal(map[string]any{"intent_id": id, "message": "new evidence", "parent_ids": []int64{fact}, "route": r})
		res, err := tools.continueIntent().Call(t.Context(), raw, nil)
		if err != nil || !res.IsError {
			t.Fatalf("expected rejection: %v %s", err, res.Flatten())
		}
		return res.Flatten()
	}
	if got := call(map[string]any{"entry": "https://example.test/other", "family": "parser"}); !strings.Contains(got, "身份") {
		t.Fatal(got)
	}
	if got := call(route); !strings.Contains(got, "queue unavailable") {
		t.Fatal(got)
	}
	after, _ := tools.ts.GetNode(id)
	if string(after.Payload) != string(before.Payload) || after.State != before.State {
		t.Fatalf("failed enqueue consumed budget: %s / %s", after.State, after.Payload)
	}
}

func TestRouteEvidenceContentDrivesContinuation(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/import", "family": "parser"}
	count := 0
	fact := func(detail string) int64 {
		count++
		id, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": fmt.Sprintf("callback %d", count), "detail": "reworded explanation", "evidence": detail, "confidence": "observed", "outcome": "progress", "route": route}, 5, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := fact("DNS probe=a remote=192.0.2.1")
	out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route, "parent_ids": []int64{first}})
	if failed {
		t.Fatal(out)
	}
	for i := 0; i < 3; i++ {
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	duplicate := fact("DNS probe=a remote=192.0.2.1")
	out, failed = callIntent(t, tools, map[string]any{"summary": "duplicate", "route": route, "parent_ids": []int64{duplicate}})
	if !failed {
		t.Fatal("duplicate content was accepted:", out)
	}
	fresh := fact("HTTP probe=b remote=192.0.2.2")
	overview, err := tools.graphOverview().Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Routes []struct {
			InformationFree int `json:"information_free"`
		} `json:"routes"`
	}
	if err := json.Unmarshal([]byte(overview.Flatten()), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Routes) != 1 || data.Routes[0].InformationFree != 0 {
		t.Fatal(overview.Flatten())
	}
	out, failed = callIntent(t, tools, map[string]any{"summary": "new evidence", "route": route, "parent_ids": []int64{fresh}})
	if failed {
		t.Fatal(out)
	}
}

func TestRouteTopLevelOutcomeStopsInheritedRoute(t *testing.T) {
	for _, outcome := range []string{"impact", "prerequisite_disproved", "variants_exhausted"} {
		t.Run(outcome, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": "https://example.test/import", "family": "parser"}
			out, failed := callIntent(t, tools, map[string]any{"summary": "initial", "route": route})
			if failed {
				t.Fatal(out)
			}
			id := parseCreatedIntentID(t, out)
			raw, _ := json.Marshal(map[string]any{"intent_id": id, "summary": "conclusive result", "confidence": "observed", "evidence": "request/response proof", "outcome": outcome})
			res, err := tools.recordFact().Call(t.Context(), raw, nil)
			if err != nil || res.IsError {
				t.Fatalf("record: %v %s", err, res.Flatten())
			}
			out, failed = callIntent(t, tools, map[string]any{"summary": "retry", "route": map[string]any{"entry": route["entry"], "family": route["family"], "tested": []string{"new variant"}}})
			if !failed {
				t.Fatal("terminal route accepted:", out)
			}
		})
	}
}
