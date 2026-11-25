package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func experimentRejected(t *testing.T, req llm.CompletionRequest, id string) {
	t.Helper()
	for i := len(req.Messages) - 1; i >= 0; i-- {
		for _, b := range req.Messages[i].Content {
			if b.Type == llm.BlockToolResult && b.ToolUseID == id {
				if !b.IsError {
					t.Fatalf("%s incorrectly accepted: %s", id, blocksText(b.Content))
				}
				return
			}
		}
	}
	t.Fatalf("missing rejected ToolResult: %s", id)
}

func TestExperimentRetryCannotBorrowPriorRun(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "same intent, different invocations")
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "retry.txt")
	var old map[string]any
	var oldRun, newRun string
	var factID int64
	probe := actool.Build(actool.Spec{Name: "fixture_read_run", Schema: obj(map[string]any{}), Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		ri := RunInfoFrom(ctx)
		if ri.RunID == "" || ri.RunID == "caller-supplied" || ri.IntentID != intentID {
			t.Errorf("tool did not receive host attribution: %+v", ri)
		}
		return actool.Text(ri.RunID), nil
	}})
	p := &experimentDriver{t: t}
	p.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("write-one", "Write", map[string]any{"file_path": path, "content": "first invocation"}),
		experimentTurn("trace-one", "get_worker_trace", map[string]any{"intent_id": intentID}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			old = experimentStep(t, experimentSteps(t, req, "trace-one"), "Write")
			oldRun = experimentRunID(t, old)
			return textTurn("first invocation finished")
		},
		experimentTurn("ctx", "fixture_read_run", map[string]any{}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			newRun = experimentResult(t, req, "ctx")
			if newRun == oldRun {
				t.Fatal("retry reused its stable transcript ID as run ID")
			}
			return toolTurn("borrow", "record_fact", map[string]any{"summary": "claim old action this run", "experiment": map[string]any{"run": map[string]any{"run_id": oldRun}, "execution_state": "executed", "execution_basis": experimentBasis(old)}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			experimentRejected(t, req, "borrow")
			return toolTurn("trace-two", "get_worker_trace", map[string]any{"intent_id": intentID})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			steps := experimentSteps(t, req, "trace-two")
			prior := experimentStep(t, steps, "Write")
			current := experimentStep(t, steps, "fixture_read_run")
			if prior["relation"] != "prior_run" || current["relation"] != "current_run" || experimentRunID(t, current) != newRun {
				t.Fatalf("run relations lost: old=%+v new=%+v", prior, current)
			}
			basis := experimentBasis(prior)
			basis["run"] = map[string]any{"run_id": "forged"}
			basis["relation"] = "current_run"
			return toolTurn("history", "record_fact", map[string]any{"summary": "old action remains historical material", "experiment": map[string]any{"execution_state": "unknown", "observation": map[string]any{"state": "incomplete"}, "references": []any{basis}}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if _, err := fmt.Sscanf(experimentResult(t, req, "history"), "fact recorded: %d", &factID); err != nil {
				t.Fatal(err)
			}
			return toolTurn("read-history", "node_detail", map[string]any{"id": factID})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			body := experimentResult(t, req, "read-history")
			for _, want := range []string{oldRun, newRun, "prior_run", "incomplete"} {
				if !strings.Contains(body, want) {
					t.Fatalf("history lost %q: %s", want, body)
				}
			}
			if strings.Contains(body, "forged") {
				t.Fatalf("forged nested run survived: %s", body)
			}
			return textTurn("retry kept old material without claiming new execution")
		},
	}
	w := NewWorker(p, "scripted-fixture", t.TempDir(), nil, 0, 10, probe)
	ctx := WithRunInfo(t.Context(), RunInfo{RunID: "caller-supplied"})
	if _, _, err := w.Execute(ctx, "worker", 7, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, writes, err := w.Execute(ctx, "worker", 7, nil, store, intent, nil, nil, nil, nil); err != nil || writes.Facts != 1 {
		t.Fatalf("retry: writes=%+v err=%v", writes, err)
	}
	if p.next != len(p.turns) {
		t.Fatal("retry orchestration did not complete")
	}
}

type experimentBlockHook struct{}

func (experimentBlockHook) PreToolUse(_ context.Context, name string, _ []byte) (bool, string, []byte) {
	return name == "fixture_local_block", "fixture action locally blocked", nil
}
func (experimentBlockHook) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (experimentBlockHook) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestExperimentErrorsAndLocalBlocksRemainIncomplete(t *testing.T) {
	for _, name := range []string{"fixture_error", "fixture_local_block", "fixture_cancelled"} {
		t.Run(name, func(t *testing.T) {
			_, store := recordFactTestStore(t)
			intentID := recordFactTestIntent(t, store, name)
			intent, err := store.GetNode(intentID)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			action := actool.Build(actool.Spec{Name: name, Schema: obj(map[string]any{}), Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
				calls++
				if name == "fixture_cancelled" {
					return actool.Result{}, context.Canceled
				}
				return actool.Errorf("fixture identity expired"), nil
			}})
			var failed map[string]any
			p := &experimentDriver{t: t}
			p.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
				experimentTurn("attempt", name, map[string]any{}),
				func(req llm.CompletionRequest) []llm.StreamEvent {
					experimentRejected(t, req, "attempt")
					return toolTurn("trace", "get_worker_trace", map[string]any{"intent_id": intentID})
				},
				func(req llm.CompletionRequest) []llm.StreamEvent {
					for _, s := range experimentSteps(t, req, "trace") {
						if s["tool"] == name && s["kind"] == "tool_result" {
							failed = s
						}
					}
					if failed == nil || failed["is_error"] != true || failed["provenance"].(map[string]any)["completed"] != false {
						t.Fatalf("failed call was marked completed: %+v", failed)
					}
					return toolTurn("false-completion", "record_fact", map[string]any{"summary": "claim failed action succeeded", "experiment": map[string]any{"observation": map[string]any{"state": "complete", "basis": experimentBasis(failed)}}})
				},
				func(req llm.CompletionRequest) []llm.StreamEvent {
					experimentRejected(t, req, "false-completion")
					return toolTurn("blocked", "record_fact", map[string]any{"summary": "incomplete experiment after failure", "experiment": map[string]any{"execution_state": "blocked", "blocker": name, "identity": map[string]any{"valid": false}, "observation": map[string]any{"state": "incomplete", "basis": experimentBasis(failed)}}})
				},
				func(req llm.CompletionRequest) []llm.StreamEvent {
					experimentResult(t, req, "blocked")
					return textTurn("failure handed off without fake completion")
				},
			}
			w := NewWorker(p, "scripted-fixture", t.TempDir(), nil, 0, 8, action)
			if _, writes, err := w.Execute(t.Context(), "worker", 7, nil, store, intent, experimentBlockHook{}, nil, nil, nil); err != nil || writes.Facts != 1 {
				t.Fatalf("failed-action handoff: writes=%+v err=%v", writes, err)
			}
			want := 1
			if name == "fixture_local_block" {
				want = 0
			}
			if calls != want || p.next != len(p.turns) {
				t.Fatalf("tool calls=%d want=%d turns=%d", calls, want, p.next)
			}
		})
	}
}
