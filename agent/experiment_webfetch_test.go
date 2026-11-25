package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestExperimentWebFetchHasRecoverableExecution(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "read the normal HTTP operation")
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("local normal operation: ready"))
	}))
	defer server.Close()
	p := &experimentDriver{t: t}
	p.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("fetch", "WebFetch", map[string]any{"url": server.URL}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "fetch"), "local normal operation: ready") {
				t.Fatal("WebFetch did not read the local response")
			}
			return toolTurn("trace", "get_worker_trace", map[string]any{"intent_id": intentID})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			step := experimentStep(t, experimentSteps(t, req, "trace"), "WebFetch")
			experimentRunID(t, step)
			return toolTurn("handoff", "record_fact", map[string]any{
				"summary": "normal HTTP operation is readable", "confidence": "observed",
				"experiment": map[string]any{
					"execution_state": "executed", "execution_basis": experimentBasis(step),
					"conclusion":  "the local normal operation returned ready",
					"observation": map[string]any{"state": "complete", "basis": experimentBasis(step), "excerpt": "local normal operation: ready"},
				},
			})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			experimentResult(t, req, "handoff")
			return textTurn("actual HTTP observation handed off")
		},
	}
	w := NewWorker(p, "scripted-fixture", t.TempDir(), nil, 0, 8)
	if _, writes, err := w.Execute(t.Context(), "worker", 7, nil, store, intent, nil, nil, nil, nil); err != nil || writes.Facts != 1 {
		t.Fatalf("WebFetch handoff: writes=%+v err=%v", writes, err)
	}
	if hits.Load() != 1 || p.next != len(p.turns) {
		t.Fatalf("HTTP requests=%d turns=%d", hits.Load(), p.next)
	}
}
