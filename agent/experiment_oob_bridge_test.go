package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Only OOB transport is a fixture here. The triggering HTTP request is real and
// restricted to httptest; the public worker tool results drive every next call.
func TestExperimentOOBSharesHostRunAndChecksAllocatedProbe(t *testing.T) {
	_, store := recordFactTestStore(t)
	intentID := recordFactTestIntent(t, store, "owned probe handoff")
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "locally received "+r.URL.Query().Get("probe_id"))
	}))
	defer server.Close()
	action := actool.Build(actool.Spec{Name: "fixture_send", Schema: obj(map[string]any{"probe_id": str("local allocated probe")}, "probe_id"), Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		var input struct {
			ProbeID string `json:"probe_id"`
		}
		if err := json.Unmarshal(in, &input); err != nil {
			return actool.Result{}, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/?probe_id="+input.ProbeID, nil)
		if err != nil {
			return actool.Result{}, err
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			return actool.Result{}, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return actool.Text(string(body)), err
	}})
	var probe, hostRun string
	var sent map[string]any
	p := &experimentDriver{t: t}
	p.turns = []func(llm.CompletionRequest) []llm.StreamEvent{
		experimentTurn("allocate", "oob_generate", map[string]any{}),
		func(req llm.CompletionRequest) []llm.StreamEvent {
			out := decode(t, experimentResult(t, req, "allocate"))
			probe = out["probes"].([]any)[0].(map[string]any)["probe_id"].(string)
			return toolTurn("send", "fixture_send", map[string]any{"probe_id": probe})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if experimentResult(t, req, "send") != "locally received "+probe {
				t.Fatal("local request was not actually received")
			}
			return toolTurn("trace", "get_worker_trace", map[string]any{"intent_id": intentID})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			steps := experimentSteps(t, req, "trace")
			sent = experimentStep(t, steps, "fixture_send")
			hostRun = experimentRunID(t, sent)
			allocation := experimentStep(t, steps, "oob_generate")
			if allocation["provenance"].(map[string]any)["completed"] != false {
				t.Fatal("allocation was counted as a completed trigger")
			}
			return toolTurn("foreign", "record_fact", map[string]any{"summary": "wrong probe claim", "experiment": map[string]any{"probe": map[string]any{"allocated": true, "probe_id": "unallocated", "send_state": "sent", "send_basis": experimentBasis(sent)}}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			experimentRejected(t, req, "foreign")
			return toolTurn("owned", "record_fact", map[string]any{"summary": "local trigger for owned probe", "experiment": map[string]any{"probe": map[string]any{"allocated": true, "probe_id": probe, "send_state": "sent", "send_basis": experimentBasis(sent)}}})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			experimentResult(t, req, "owned")
			return toolTurn("poll", "oob_poll", map[string]any{"probe_id": probe, "wait": 1})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			out := decode(t, experimentResult(t, req, "poll"))
			observation := out["observation"].(map[string]any)
			if observation["run_id"] != hostRun || !strings.HasPrefix(observation["window_id"].(string), hostRun+"/") {
				t.Fatalf("OOB kept an independent run ID: host=%s observation=%+v", hostRun, observation)
			}
			return toolTurn("oob-fact", "node_detail", map[string]any{"id": out["fact_id"]})
		},
		func(req llm.CompletionRequest) []llm.StreamEvent {
			if !strings.Contains(experimentResult(t, req, "oob-fact"), hostRun) {
				t.Fatal("OOB fact lost host origin")
			}
			return textTurn("owned probe and existing activity share a run")
		},
	}
	w := NewWorker(p, "scripted-fixture", t.TempDir(), nil, 0, 12, action)
	w.SetOOBSessionFactory(func() (oobSession, func(), error) {
		s := &fakeSession{url: "local.example.test", interactions: []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1"}}}
		return s, func() { _ = s.Close() }, nil
	})
	if _, writes, err := w.Execute(t.Context(), "worker", 7, nil, store, intent, nil, nil, nil, nil); err != nil || writes.Facts != 2 {
		t.Fatalf("probe handoff: writes=%+v err=%v", writes, err)
	}
	if p.next != len(p.turns) {
		t.Fatal("probe orchestration did not finish")
	}
}
