package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type routeProgressAttempt struct {
	input   map[string]any // nil reuses the preceding successful activity
	excerpt string
}

// The tool reads distinct local objects. Both deny access, so the recorded
// operation (not the response wording) distinguishes the two experiments.
func routeProgressFacts(t *testing.T, tools *ToolSet, attempts ...routeProgressAttempt) []int64 {
	t.Helper()
	dir := t.TempDir()
	for _, object := range []string{"own", "other"} {
		if err := os.WriteFile(filepath.Join(dir, object), []byte("status=403"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	local := actool.Build(actool.Spec{
		Name: "fixture_read_object", Schema: obj(map[string]any{"object": str("local object"), "nonce": str("correlation only")}),
		Run: func(_ context.Context, raw json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct{ Object, Nonce string }
			if err := json.Unmarshal(raw, &in); err != nil {
				return actool.Result{}, err
			}
			if in.Object != "own" && in.Object != "other" {
				return actool.Result{}, fmt.Errorf("unknown local object %q", in.Object)
			}
			content, err := os.ReadFile(filepath.Join(dir, in.Object))
			if err != nil {
				return actool.Result{}, err
			}
			return actool.Text(string(content) + " nonce=" + in.Nonce), nil
		},
	})
	intentID := recordFactTestIntent(t, tools.ts, "read local comparison objects")
	intent, err := tools.ts.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, len(attempts))
	capture := func(req llm.CompletionRequest, i int) {
		if i < 0 {
			return
		}
		if _, err := fmt.Sscanf(experimentResult(t, req, fmt.Sprintf("fact-%d", i)), "fact recorded: %d", &ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	var basis map[string]any
	provider := &experimentDriver{t: t}
	for i, attempt := range attempts {
		if attempt.input != nil {
			provider.turns = append(provider.turns, func(req llm.CompletionRequest) []llm.StreamEvent {
				capture(req, i-1)
				return toolTurn(fmt.Sprintf("read-%d", i), local.Name(), attempt.input)
			}, experimentTurn(fmt.Sprintf("trace-%d", i), "get_worker_trace", map[string]any{"intent_id": intentID}))
		}
		provider.turns = append(provider.turns, func(req llm.CompletionRequest) []llm.StreamEvent {
			if attempt.input == nil {
				capture(req, i-1)
			} else {
				steps := experimentSteps(t, req, fmt.Sprintf("trace-%d", i))
				for j := len(steps) - 1; j >= 0; j-- {
					if steps[j]["tool"] == local.Name() && steps[j]["kind"] == "tool_result" {
						basis = experimentBasis(steps[j])
						break
					}
				}
			}
			return toolTurn(fmt.Sprintf("fact-%d", i), "record_fact", map[string]any{
				"summary": fmt.Sprintf("renamed handoff %d", i), "confidence": "observed", "evidence": attempt.excerpt,
				"experiment": map[string]any{
					"execution_state": "executed", "execution_basis": basis,
					"variables":   map[string]any{"label": fmt.Sprintf("variant-%d", i), "nonce": fmt.Sprint(i)},
					"observation": map[string]any{"state": "complete", "basis": basis, "excerpt": attempt.excerpt},
					"conclusion":  "local object response recovered",
				},
			})
		})
	}
	provider.turns = append(provider.turns, func(req llm.CompletionRequest) []llm.StreamEvent {
		capture(req, len(attempts)-1)
		return textTurn("local observations saved")
	})
	taskID, _ := tools.ts.TaskID()
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, len(provider.turns)+2, local)
	if _, _, err := worker.Execute(t.Context(), "worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestRouteProgressIdentitySameActivity(t *testing.T) {
	for _, seam := range []string{"add_intent", "continue_intent"} {
		t.Run(seam, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			facts := routeProgressFacts(t, tools,
				routeProgressAttempt{map[string]any{"object": "own", "nonce": "alpha"}, "响应为403"},
				routeProgressAttempt{nil, "收到403响应"},
			)
			route := map[string]any{"entry": "https://example.test/object", "family": "authorization"}
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
				"summary": "follow first observation", "route": route, "parent_ids": []int64{facts[0]},
			})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			id := parseCreatedIntentID(t, created.Flatten())
			if err := tools.ts.SetIntentState(id, "done"); err != nil {
				t.Fatal(err)
			}
			// Reassembly must recover consumed identity from the durable activities.
			restored := NewToolSet(tools.ts, "planner")
			queued := false
			restored.SetContinueWork(func(int64, string) error { queued = true; return nil })
			out := operationTool(t, restored.PlannerTools(), seam, map[string]any{
				"summary": "renamed observation", "intent_id": id, "message": "use reworded observation",
				"route": route, "parent_ids": []int64{facts[1]},
			})
			if !out.IsError || !strings.Contains(out.Flatten(), "没有新增事实") || queued {
				t.Fatalf("same activity gained another continuation: queued=%v %s", queued, out.Flatten())
			}
		})
	}
}

func TestRouteProgressIdentityActualOperation(t *testing.T) {
	for _, tc := range []struct {
		name, object, nonce string
		wantNew             bool
	}{
		{"repeated_action_new_run", "own", "alpha", false},
		{"correlation_only", "own", "beta", false},
		{"different_object_same_response", "other", "alpha", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			first := routeProgressFacts(t, tools, routeProgressAttempt{
				map[string]any{"object": "own", "nonce": "alpha"}, "响应为403",
			})[0]
			route := map[string]any{"entry": "https://example.test/object", "family": "authorization"}
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
				"summary": "follow first observation", "route": route, "parent_ids": []int64{first},
			})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			next := routeProgressFacts(t, tools, routeProgressAttempt{
				map[string]any{"object": tc.object, "nonce": tc.nonce}, "响应为403",
			})[0]
			out := operationTool(t, NewToolSet(tools.ts, "planner").PlannerTools(), "add_intent", map[string]any{
				"summary": "follow actual comparison", "route": route, "parent_ids": []int64{next},
			})
			if out.IsError == tc.wantNew {
				t.Fatalf("actual operation new=%v, got %s", tc.wantNew, out.Flatten())
			}
		})
	}
}
