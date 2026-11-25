package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Exercise host execution stamps through Worker.Execute; no model or network is
// involved. Existing lower-level route fixtures can reuse the same real handoff.
func routeObservationFact(t *testing.T, tools *ToolSet, intentID int64, payload map[string]any, message ...string) int64 {
	t.Helper()
	if intentID == 0 {
		var err error
		intentID, err = tools.ts.AddIntent(map[string]any{"summary": "recover local observation fixture"}, 1, nil, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
			t.Fatal(err)
		}
	}
	excerpt, _ := payload["evidence"].(string)
	if excerpt == "" {
		excerpt = "control=normal; variant=parsed"
		payload["evidence"] = excerpt
	}
	path := filepath.Join(t.TempDir(), "observation.txt")
	if err := os.WriteFile(path, []byte(excerpt), 0600); err != nil {
		t.Fatal(err)
	}
	intent, err := tools.ts.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatalf("intent %d: %v", intentID, err)
	}
	var factID int64
	provider := &experimentDriver{t: t}
	provider.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("observe", "Read", map[string]any{"file_path": path}),
		experimentTurn("trace", "get_worker_trace", map[string]any{"intent_id": intentID}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			steps := experimentSteps(t, req, "trace")
			// The same intent may already contain successful reads from prior runs.
			// get_worker_trace is oldest-first; select this run's newest result.
			for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
				steps[i], steps[j] = steps[j], steps[i]
			}
			step := experimentStep(t, steps, "Read")
			payload["experiment"] = map[string]any{
				"execution_state": "executed", "execution_basis": experimentBasis(step),
				"observation": map[string]any{"state": "complete", "basis": experimentBasis(step), "excerpt": excerpt},
				"conclusion":  "the local observation was recovered",
			}
			return toolTurn("fact", "record_fact", payload)
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if _, err := fmt.Sscanf(experimentResult(t, req, "fact"), "fact recorded: %d", &factID); err != nil {
				t.Fatal(err)
			}
			return textTurn("observation saved")
		},
	}
	taskID, _ := tools.ts.TaskID()
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 8)
	if len(message) > 0 {
		_, _, err = worker.ExecuteWithMessage(t.Context(), "worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil, "fixture-resume", message[0])
	} else {
		_, _, err = worker.Execute(t.Context(), "worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return factID
}

func TestRouteConclusionNeedsLocatableObservation(t *testing.T) {
	for _, outcome := range []string{"impact", "negative", "prerequisite_disproved", "variants_exhausted"} {
		t.Run(outcome, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
				"summary": "check the parser", "route": map[string]any{"entry": "https://example.test/parser", "family": "parser"},
			})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			worker := NewToolSet(tools.ts, "worker")
			worker.SetOwnerNode(parseCreatedIntentID(t, created.Flatten()))
			out := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{
				"summary": "an old conclusion remains readable", "outcome": outcome,
				"confidence": "observed", "evidence": "model-authored claim, no retrievable observation",
			})
			if out.IsError {
				t.Fatal(out.Flatten())
			}
			// Reassemble the planner: replay must not invent support for old facts.
			rows := readOperations(t, NewToolSet(tools.ts, "planner")).Routes
			if len(rows) != 1 || rows[0].Stopped {
				t.Fatalf("unsupported conclusion acquired stop authority: %+v", rows)
			}
		})
	}
}

func TestRouteConclusionReplaysSuccessfulObservation(t *testing.T) {
	for _, outcome := range []string{"impact", "negative", "prerequisite_disproved", "variants_exhausted"} {
		t.Run(outcome, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": "https://example.test/parser", "family": "parser"}
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "check parser", "route": route})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			routeObservationFact(t, tools, parseCreatedIntentID(t, created.Flatten()), map[string]any{
				"summary": "completed comparison", "confidence": "observed", "outcome": outcome,
			})
			restored := NewToolSet(tools.ts, "planner")
			rows := readOperations(t, restored).Routes
			if len(rows) != 1 || !rows[0].Stopped {
				t.Fatalf("supported conclusion was lost: %+v", rows)
			}
			out := operationTool(t, restored.PlannerTools(), "add_intent", map[string]any{"summary": "renamed", "route": route})
			if !out.IsError || !strings.Contains(out.Flatten(), "停止") {
				t.Fatalf("supported conclusion did not stop admission: %s", out.Flatten())
			}
		})
	}
}

func TestRouteTestedLabelDoesNotGrantContinuation(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/parser", "family": "parser"}
	first := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "initial plan", "route": route})
	if first.IsError {
		t.Fatal(first.Flatten())
	}
	id := parseCreatedIntentID(t, first.Flatten())
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	route["tested"] = []string{"new label, no execution"}
	route["remaining"] = []string{"read the normal response"}
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "rename the plan", "route": route})
	if !out.IsError {
		t.Fatalf("tested label granted another execution: %s", out.Flatten())
	}
}

func TestRouteContinuationRequiresExecutedObservation(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/parser", "family": "parser"}
	first := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "initial plan", "route": route})
	if first.IsError {
		t.Fatal(first.Flatten())
	}
	id := parseCreatedIntentID(t, first.Flatten())
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(id)
	for _, state := range []string{"planned", "blocked", "unknown"} {
		out := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{
			"summary": "new words are not execution", "confidence": "observed", "evidence": "new nonce and a claimed observation: " + state,
			"experiment": map[string]any{"execution_state": state, "observation": map[string]any{"state": "incomplete"}},
		})
		if out.IsError {
			t.Fatal(out.Flatten())
		}
		var factID int64
		if _, err := fmt.Sscanf(out.Flatten(), "fact recorded: %d", &factID); err != nil {
			t.Fatal(err)
		}
		out = operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "continue", "route": route, "parent_ids": []int64{factID}})
		if !out.IsError {
			t.Fatalf("%s fact granted continuation: %s", state, out.Flatten())
		}
	}
}

func TestRouteNonceDoesNotBecomeInformationGain(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/parser", "family": "parser"}
	first := routeObservationFact(t, tools, 0, map[string]any{"summary": "first callback", "confidence": "observed", "evidence": "DNS callback nonce=alpha remote=192.0.2.1", "route": route})
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "follow callback", "route": route, "parent_ids": []int64{first}})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	duplicate := routeObservationFact(t, tools, 0, map[string]any{"summary": "renamed callback", "confidence": "observed", "evidence": "DNS callback nonce=beta remote=192.0.2.1", "route": route})
	out := operationTool(t, NewToolSet(tools.ts, "planner").PlannerTools(), "add_intent", map[string]any{"summary": "only nonce changed", "route": route, "parent_ids": []int64{duplicate}})
	if !out.IsError {
		t.Fatalf("nonce granted continuation: %s", out.Flatten())
	}
}
