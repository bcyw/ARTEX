package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/db"
)

// The provider only schedules calls and consumes their real ToolResults. It is
// not a model-quality test. Files, tool execution, facts, and SQLite are real.
type experimentDriver struct {
	t     *testing.T
	turns []func(llm.CompletionRequest) []llm.StreamEvent
	next  int
}

func (p *experimentDriver) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	var events []llm.StreamEvent
	if p.next < len(p.turns) {
		step := p.next
		p.next++
		events = p.turns[step](req)
	} else {
		events = textTurn("fixture finished")
	}
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, e := range events {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func (p *experimentDriver) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func experimentTurn(id, name string, input any) func(llm.CompletionRequest) []llm.StreamEvent {
	return func(llm.CompletionRequest) []llm.StreamEvent { return toolTurn(id, name, input) }
}

func experimentResult(t *testing.T, req llm.CompletionRequest, id string) string {
	t.Helper()
	for i := len(req.Messages) - 1; i >= 0; i-- {
		for _, b := range req.Messages[i].Content {
			if b.Type == llm.BlockToolResult && b.ToolUseID == id {
				if b.IsError {
					t.Fatalf("%s failed: %s", id, blocksText(b.Content))
				}
				return blocksText(b.Content)
			}
		}
	}
	t.Fatalf("missing real ToolResult for %s", id)
	return ""
}

func experimentSteps(t *testing.T, req llm.CompletionRequest, id string) []map[string]any {
	t.Helper()
	var trace struct {
		Steps []map[string]any `json:"steps"`
	}
	if err := json.Unmarshal([]byte(experimentResult(t, req, id)), &trace); err != nil {
		t.Fatal(err)
	}
	return trace.Steps
}

func experimentStep(t *testing.T, steps []map[string]any, tool string) map[string]any {
	t.Helper()
	for _, s := range steps {
		if s["tool"] == tool && s["kind"] == "tool_result" && s["is_error"] == false {
			return s
		}
	}
	t.Fatalf("successful %s step missing from public trace: %+v", tool, steps)
	return nil
}

func experimentBasis(step map[string]any) map[string]any {
	return map[string]any{"kind": "activity", "id": step["step_id"]}
}

func experimentRunID(t *testing.T, step map[string]any) string {
	t.Helper()
	p, _ := step["provenance"].(map[string]any)
	run, _ := p["run"].(map[string]any)
	id, _ := run["run_id"].(string)
	if id == "" || p["completed"] != true {
		t.Fatalf("host run/completion missing: %+v", step)
	}
	return id
}

func TestExperimentRealDelayedHandoff(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "experiment.sqlite")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("local delayed fixture", "save a document, process later, read output", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	store := d.Exploration(task.ExplorationID)
	intentID := recordFactTestIntent(t, store, "save a normal document for later processing")
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	saved, observed := filepath.Join(files, "saved.txt"), filepath.Join(files, "observed.txt")
	const document = "normal operation baseline\ndelayed marker: seven\n"
	var firstRun string
	var firstFact int64
	var savedStep map[string]any
	p := &experimentDriver{t: t}
	p.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("save", "Write", map[string]any{"file_path": saved, "content": document}),
		experimentTurn("baseline", "Read", map[string]any{"file_path": saved}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "baseline"), "delayed marker: seven") {
				t.Fatal("baseline was not actually read")
			}
			return toolTurn("trace", "get_worker_trace", map[string]any{"intent_id": intentID})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			steps := experimentSteps(t, req, "trace")
			savedStep = experimentStep(t, steps, "Write")
			read := experimentStep(t, steps, "Read")
			firstRun = experimentRunID(t, savedStep)
			if experimentRunID(t, read) != firstRun {
				t.Fatal("one worker invocation got multiple run IDs")
			}
			return toolTurn("handoff", "record_fact", map[string]any{
				"summary": "normal document saved; delayed processing still pending",
				"experiments": []any{
					map[string]any{"question": "normal operation baseline", "normal_operation": "save and read document", "execution_state": "executed", "execution_basis": experimentBasis(savedStep), "observation": map[string]any{"state": "complete", "basis": experimentBasis(read), "excerpt": "normal operation baseline"}},
					map[string]any{"question": "does later processing consume the saved document?", "execution_state": "planned", "actions": []any{map[string]any{"state": "executed", "description": "save document", "basis": experimentBasis(savedStep)}}, "observation": map[string]any{"state": "incomplete", "position": observed}, "references": []any{experimentBasis(savedStep)}},
				},
			})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if _, err := fmt.Sscanf(experimentResult(t, req, "handoff"), "fact recorded: %d", &firstFact); err != nil {
				t.Fatal(err)
			}
			return textTurn("saved and awaiting later trigger")
		},
	}
	worker := NewWorker(p, "scripted-fixture", t.TempDir(), nil, 0, 8)
	// No HTTP capture, transcript or external activity sink is configured.
	if _, writes, err := worker.Execute(t.Context(), "worker", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil || writes.Facts != 1 {
		t.Fatalf("save run: writes=%+v err=%v", writes, err)
	}
	if _, err := os.Stat(observed); !os.IsNotExist(err) {
		t.Fatal("delayed output existed before the trigger")
	}
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store = d.Exploration(task.ExplorationID)
	var nextIntent int64
	plannerProvider := &experimentDriver{t: t}
	plannerProvider.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("facts", "list_facts", map[string]any{}),
		experimentTurn("recover", "node_detail", map[string]any{"id": firstFact}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			result := experimentResult(t, req, "recover")
			for _, want := range []string{firstRun, "normal operation baseline", "incomplete", "does later processing consume"} {
				if !strings.Contains(result, want) {
					t.Fatalf("planner missed %q: %s", want, result)
				}
			}
			return toolTurn("old-detail", "get_worker_trace", map[string]any{"intent_id": intentID, "step_ids": []any{savedStep["step_id"]}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "old-detail"), firstRun) {
				t.Fatal("full activity lost its origin on SQLite reopen")
			}
			return toolTurn("next", "add_intent", map[string]any{"summary": "trigger saved document and read output", "parent_ids": []int64{firstFact}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			nextIntent = parseCreatedIntentID(t, experimentResult(t, req, "next"))
			return textTurn("delayed work scheduled")
		},
	}
	planner := NewPlanner(plannerProvider, "scripted-fixture", t.TempDir(), nil, 0, 8)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, store, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intent, err = store.GetNode(nextIntent)
	if err != nil || intent == nil {
		t.Fatalf("followup intent missing: %v", err)
	}
	trigger := actool.Build(actool.Spec{Name: "fixture_process_saved", Schema: obj(map[string]any{}), Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		b, err := os.ReadFile(saved)
		if err != nil {
			return actool.Result{}, err
		}
		if err := os.WriteFile(observed, []byte(strings.ToUpper(string(b))), 0600); err != nil {
			return actool.Result{}, err
		}
		return actool.Text("saved document processed into " + observed), nil
	}})
	var secondRun string
	var secondFact int64
	next := &experimentDriver{t: t}
	next.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("recover", "node_detail", map[string]any{"id": firstFact}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "recover"), observed) {
				t.Fatal("next worker did not recover observation location")
			}
			return toolTurn("trigger", "fixture_process_saved", map[string]any{})
		},
		experimentTurn("observe", "Read", map[string]any{"file_path": observed}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "observe"), "DELAYED MARKER: SEVEN") {
				t.Fatal("delayed processing was not actually observed")
			}
			return toolTurn("trace", "get_worker_trace", map[string]any{"intent_id": nextIntent})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			steps := experimentSteps(t, req, "trace")
			action, read := experimentStep(t, steps, "fixture_process_saved"), experimentStep(t, steps, "Read")
			secondRun = experimentRunID(t, action)
			if secondRun == firstRun || experimentRunID(t, read) != secondRun {
				t.Fatal("host did not distinguish worker invocations")
			}
			return toolTurn("observed-fact", "record_fact", map[string]any{"summary": "saved document consumed by later local processing", "experiment": map[string]any{
				"question": "does later processing consume the saved document?", "run": map[string]any{"run_id": "model-forgery"}, "execution_state": "executed", "execution_basis": experimentBasis(action),
				"observation": map[string]any{"state": "complete", "position": observed, "excerpt": "DELAYED MARKER: SEVEN", "basis": experimentBasis(read)},
				"references":  []any{map[string]any{"kind": "node", "id": firstFact}, experimentBasis(savedStep)},
			}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if _, err := fmt.Sscanf(experimentResult(t, req, "observed-fact"), "fact recorded: %d", &secondFact); err != nil {
				t.Fatal(err)
			}
			return toolTurn("verify", "node_detail", map[string]any{"id": secondFact})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			result := experimentResult(t, req, "verify")
			if !strings.Contains(result, secondRun) || strings.Contains(result, "model-forgery") {
				t.Fatalf("fact provenance is not host-owned: %s", result)
			}
			for _, want := range []string{firstRun, "other_intent", "DELAYED MARKER: SEVEN"} {
				if !strings.Contains(result, want) {
					t.Fatalf("handoff missing %q: %s", want, result)
				}
			}
			return textTurn("delayed observation complete")
		},
	}
	worker = NewWorker(next, "scripted-fixture", t.TempDir(), nil, 0, 10, trigger)
	if _, writes, err := worker.Execute(t.Context(), "worker", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil || writes.Facts != 1 {
		t.Fatalf("observe run: writes=%+v err=%v", writes, err)
	}
	if p.next != len(p.turns) || next.next != len(next.turns) || plannerProvider.next != len(plannerProvider.turns) {
		t.Fatal("scripted orchestration ended before completing the real handoff")
	}
}
