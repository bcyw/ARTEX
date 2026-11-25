package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestWorkerTechnicalCompletionCannotBeAnAssetWrite(t *testing.T) {
	for _, technical := range []bool{false, true} {
		name := "recon"
		if technical {
			name = "technical"
		}
		t.Run(name, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			payload := map[string]any{"summary": "inspect local fixture"}
			if technical {
				payload["route"] = map[string]any{"entry": "https://example.test/parser", "family": "parser"}
			}
			created := operationTool(t, tools.PlannerTools(), "add_intent", payload)
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			intent, err := tools.ts.GetNode(parseCreatedIntentID(t, created.Flatten()))
			if err != nil {
				t.Fatal(err)
			}
			provider := &experimentDriver{t: t, turns: []func(llm.CompletionRequest) []llm.StreamEvent{
				experimentTurn("asset", "insert_assets", map[string]any{"assets": []any{map[string]any{"type": "endpoint", "url": "https://example.test/parser", "method": "POST"}}}),
				func(req llm.CompletionRequest) []llm.StreamEvent {
					experimentResult(t, req, "asset")
					return textTurn("asset saved")
				},
			}}
			worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 8)
			_, writes, err := worker.Execute(t.Context(), "worker", tools.taskID, tools.ts.DB().Assets(), tools.ts, intent, nil, nil, nil, nil)
			if writes.Assets != 1 {
				t.Fatalf("asset fixture failed: writes=%+v err=%v", writes, err)
			}
			if technical && (err == nil || !strings.Contains(err.Error(), "finalization failed")) {
				t.Fatalf("asset satisfied technical completion: %v", err)
			}
			if !technical && err != nil {
				t.Fatalf("pure asset recon was rejected: %v", err)
			}
		})
	}
}

func TestWorkerFinalizationCannotLaunchAnotherProbe(t *testing.T) {
	tools := intentTypeToolSet(t)
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "inspect parser", "route": map[string]any{"entry": "https://example.test/parser", "family": "parser"}})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	intent, _ := tools.ts.GetNode(parseCreatedIntentID(t, created.Flatten()))
	marker := filepath.Join(t.TempDir(), "unwanted-probe")
	provider := &experimentDriver{t: t, turns: []func(llm.CompletionRequest) []llm.StreamEvent{
		func(llm.CompletionRequest) []llm.StreamEvent { return textTurn("I am done without a conclusion") },
		experimentTurn("probe", "Bash", map[string]any{"command": "touch '" + marker + "'"}),
		experimentTurn("blocked", "record_fact", map[string]any{"summary": "missing fixture response", "experiment": map[string]any{"execution_state": "blocked", "observation": map[string]any{"state": "incomplete"}, "blocker": "the fixture response for the selected operation is unavailable"}}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			experimentResult(t, req, "blocked")
			return textTurn("blocker saved")
		},
	}}
	worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 8)
	if _, _, err := worker.Execute(t.Context(), "worker", tools.taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("finalization launched another probe: %v", err)
	}
}

func TestWorkerCurrentRunCannotReusePriorConclusionOrEmptyOOB(t *testing.T) {
	for _, mode := range []string{"prior_run", "empty_oob", "current_blocker"} {
		t.Run(mode, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "inspect parser", "route": map[string]any{"entry": "https://example.test/parser", "family": "parser"}})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			id := parseCreatedIntentID(t, created.Flatten())
			intent, _ := tools.ts.GetNode(id)
			provider := &scriptedProvider{}
			if mode == "prior_run" {
				routeObservationFact(t, tools, id, map[string]any{"summary": "previous run conclusion", "confidence": "observed"})
			}
			if mode == "empty_oob" {
				provider.add(toolTurn("allocate", "oob_generate", map[string]any{})...)
				provider.add(toolTurn("poll", "oob_poll", map[string]any{"wait": 1})...)
			}
			if mode == "current_blocker" {
				provider.add(toolTurn("blocker", "record_fact", map[string]any{"summary": "missing valid identity", "experiment": map[string]any{"execution_state": "blocked", "blocker": "the required authenticated fixture identity is unavailable", "observation": map[string]any{"state": "incomplete"}}})...)
			}
			provider.add(textTurn("done")...)
			worker := NewWorker(provider, "fixture", t.TempDir(), nil, 0, 6)
			worker.SetOOBSessionFactory(func() (oobSession, func(), error) { return &fakeSession{url: "nonce.example.test"}, func() {}, nil })
			_, _, err := worker.Execute(t.Context(), "worker", tools.taskID, nil, tools.ts, intent, nil, nil, nil, nil)
			if mode == "current_blocker" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "finalization failed") {
				t.Fatalf("%s satisfied current-run completion: %v", mode, err)
			}
			if mode == "empty_oob" {
				ids, _ := tools.ts.FactsYielded(id)
				if len(ids) != 1 {
					t.Fatalf("automatic OOB fact missing: %v", ids)
				}
				node, _ := tools.ts.GetNode(ids[0])
				var p map[string]any
				_ = json.Unmarshal(node.Payload, &p)
				if p["outcome"] != "no_interaction" {
					t.Fatalf("OOB fixture: %s", node.Payload)
				}
			}
		})
	}
}
