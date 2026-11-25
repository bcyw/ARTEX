package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/internal/oob"
)

func callOOB(t *testing.T, tools []actool.CoreTool, name string, ctx context.Context, args string) map[string]any {
	t.Helper()
	for _, tool := range tools {
		if tool.Name() != name {
			continue
		}
		result, err := tool.Call(ctx, json.RawMessage(args), nil)
		if err != nil || result.IsError {
			t.Fatalf("%s: %v %s", name, err, result.Flatten())
		}
		return decode(t, result.Flatten())
	}
	t.Fatalf("tool %s missing", name)
	return nil
}

func TestOOBClosedProbeDoesNotConsumeBufferedInteraction(t *testing.T) {
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "closed observation"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	session := newDeliverLive(t, &deliverFake{
		url: "owned.example.test", dedup: 1,
		interactions: []oob.Interaction{{Protocol: "dns", FullID: "owned.example.test", Timestamp: time.Now()}},
	})
	tools := oobToolsForRun(worker, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"oob_poll", "oob_generate"} {
		out := callOOB(t, tools, name, t.Context(), `{"probe_id":"owned","wait":1}`)
		if out["status"] != "observation_incomplete" {
			t.Errorf("%s on closed run must remain incomplete, including buffered events: %v", name, out)
		}
	}
}

func TestOOBPollCancellationIsIncomplete(t *testing.T) {
	session := newDeliverLive(t, &deliverFake{url: "owned.example.test"})
	t.Cleanup(func() { _ = session.Close() })
	tools := oobToolsForRun(&ToolSet{}, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	start := time.Now()
	out := callOOB(t, tools, "oob_poll", ctx, `{"probe_id":"owned","wait":1}`)
	if out["status"] != "observation_incomplete" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("cancel must interrupt the observation without a healthy result: %v elapsed=%v", out, time.Since(start))
	}

	out = callOOB(t, tools, "oob_generate", ctx, `{}`)
	if out["status"] != "observation_incomplete" {
		t.Fatalf("cancelled generation must not allocate probes: %v", out)
	}
}

type windowSource struct {
	deliverFake
	healthy bool
	pollErr error
}

func (s *windowSource) Health() (int64, error, time.Time, time.Time) {
	if s.pollErr != nil {
		return 1, s.pollErr, time.Now(), time.Time{}
	}
	if s.healthy {
		return 0, nil, time.Time{}, time.Now()
	}
	return 0, nil, time.Time{}, time.Time{}
}

func TestOOBFilteredWindowDoesNotEndOnOtherProbe(t *testing.T) {
	for _, tc := range []struct {
		name    string
		healthy bool
		pollErr error
		status  string
	}{
		{"healthy", true, nil, "ok"},
		{"incomplete", false, nil, "observation_incomplete"},
		{"failure", false, errors.New("fixture poll unavailable"), "service_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &windowSource{
				deliverFake: deliverFake{dedup: 2, interactions: []oob.Interaction{
					{Protocol: "dns", FullID: "other.example.test", Timestamp: time.Now()},
				}},
				healthy: tc.healthy, pollErr: tc.pollErr,
			}
			session, err := newLiveSessionFrom(&fakeURLClient{urls: []string{"selected.example.test", "other.example.test"}}, src, time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.Close() })
			tools := oobToolsForRun(&ToolSet{}, session)
			callOOB(t, tools, "oob_generate", t.Context(), `{"count":2}`)
			start := time.Now()
			out := callOOB(t, tools, "oob_poll", t.Context(), `{"probe_id":"selected","wait":1}`)
			if out["status"] != tc.status || (tc.healthy && time.Since(start) < 950*time.Millisecond) {
				t.Fatalf("other probe cannot complete selected empty window: %v elapsed=%v", out, time.Since(start))
			}
			out = callOOB(t, tools, "oob_poll", t.Context(), `{"probe_id":"other","wait":1}`)
			if out["status"] != "ok" || len(out["interactions"].([]any)) != 1 {
				t.Fatalf("other probe must remain available exactly once: %v", out)
			}
		})
	}
}

func TestOOBPollDropsUnknownAndDuplicateCallbacks(t *testing.T) {
	event := OOBInteraction{Protocol: "dns", UniqueID: "probe-1", FullID: "probe-1.example.test", TimestampISO: time.Now().UTC().Format(time.RFC3339Nano)}
	session := &fakeSession{url: "example.test", interactions: []OOBInteraction{
		event, event, {Protocol: "dns", UniqueID: "foreign", FullID: "foreign.example.test"},
	}}
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "callback ownership"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	tools := oobToolsForRun(worker, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	out := callOOB(t, tools, "oob_poll", t.Context(), `{"wait":1}`)
	if len(out["interactions"].([]any)) != 1 || out["ignored_interactions"] != float64(1) {
		t.Fatalf("only one owned callback may become progress: %v", out)
	}
	fact, err := worker.ts.GetNode(int64(out["fact_id"].(float64)))
	if err != nil || fact == nil {
		t.Fatalf("callback fact: %v", err)
	}
	if strings.Contains(string(fact.Payload), "foreign") {
		t.Fatalf("unknown callback contaminated route fact: %s", fact.Payload)
	}
	session.interactions = []OOBInteraction{event}
	out = callOOB(t, tools, "oob_poll", t.Context(), `{"wait":1}`)
	if len(out["interactions"].([]any)) != 0 {
		t.Fatalf("redelivery must not become new progress: %v", out)
	}
}

func TestOOBUnallocatedAndUnknownProbeDoNotPollOrWrite(t *testing.T) {
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "unallocated observation"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	lazy := newLazySession(oob.Config{})
	lazy.new = func(context.Context) (*oob.Session, error) {
		t.Fatal("invalid observation must not register a session")
		return nil, errors.New("unexpected registration")
	}
	tools := oobToolsForRun(worker, lazy)
	if out := callOOB(t, tools, "oob_poll", t.Context(), `{"wait":1}`); out["status"] != "observation_incomplete" {
		t.Fatalf("unallocated observation: %v", out)
	}
	if out := callOOB(t, tools, "oob_poll", t.Context(), `{"probe_id":"unknown","wait":1}`); out["status"] != "unknown_probe" {
		t.Fatalf("unknown observation: %v", out)
	}
	if ids, err := worker.ts.FactsYielded(intentID); err != nil || len(ids) != 0 {
		t.Fatalf("invalid observations must not create facts: %v %v", ids, err)
	}
}

func TestOOBFactsRetainIntentProbeAndWindow(t *testing.T) {
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "window provenance"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	session := &fakeSession{url: "example.test"}
	tools := oobToolsForRun(worker, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	if ids, err := worker.ts.FactsYielded(intentID); err != nil || len(ids) != 0 {
		t.Fatalf("allocation is not a sent request or observation: %v %v", ids, err)
	}
	var runID, lastWindow string
	for _, outcome := range []string{"no_interaction", "progress", "observation_incomplete"} {
		ctx := t.Context()
		if outcome == "progress" {
			session.interactions = []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1", TimestampISO: time.Now().UTC().Format(time.RFC3339Nano)}}
		}
		if outcome == "observation_incomplete" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		out := callOOB(t, tools, "oob_poll", ctx, `{"probe_id":"probe-1","wait":1}`)
		id, ok := out["fact_id"].(float64)
		if !ok {
			t.Fatalf("missing persisted observation: %v", out)
		}
		fact, err := worker.ts.GetNode(int64(id))
		if err != nil {
			t.Fatal(err)
		}
		payload := decode(t, string(fact.Payload))
		observation, ok := payload["oob"].(map[string]any)
		if !ok || payload["intent_id"] != float64(intentID) || payload["outcome"] != outcome {
			t.Fatalf("fact must retain explicit intent and observation context: %s", fact.Payload)
		}
		if observation["phase"] != "observation" || observation["window_id"] == "" || observation["window_id"] == lastWindow || observation["run_id"] == "" {
			t.Fatalf("observation must be locatable across runs/windows: %v", observation)
		}
		ids := observation["probe_ids"].([]any)
		if len(ids) != 1 || ids[0] != "probe-1" || observation["requested_wait_ms"] != float64(1000) {
			t.Fatalf("probe and requested window missing: %v", observation)
		}
		start, err := time.Parse(time.RFC3339Nano, observation["started_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		end, err := time.Parse(time.RFC3339Nano, observation["ended_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if end.Before(start) || observation["complete"] != (outcome == "no_interaction") {
			t.Fatalf("window bounds/completion must reflect actual observation: %v", observation)
		}
		if runID != "" && observation["run_id"] != runID {
			t.Fatalf("one tool assembly must share its run identity: %v", observation)
		}
		runID = observation["run_id"].(string)
		lastWindow = observation["window_id"].(string)
	}
}

type cancelGenerateSession struct{ fakeSession }

func (s *cancelGenerateSession) GenerateContext(ctx context.Context) (string, string, error) {
	<-ctx.Done()
	return "", "", ctx.Err()
}

func TestOOBGenerateHonorsInFlightCancellation(t *testing.T) {
	session := &cancelGenerateSession{}
	tools := oobToolsForRun(&ToolSet{}, session)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	out := callOOB(t, tools, "oob_generate", ctx, `{}`)
	if out["status"] != "observation_incomplete" || len(out["probes"].([]any)) != 0 {
		t.Fatalf("cancelled allocation must not return a usable probe: %v", out)
	}
}

type signalledSession struct {
	*liveSession
	entered chan struct{}
	once    sync.Once
}

func (s *signalledSession) PollContext(ctx context.Context, wait time.Duration) ([]OOBInteraction, error) {
	s.once.Do(func() { close(s.entered) })
	return s.liveSession.PollContext(ctx, wait)
}

func TestOOBQueuedCallCancellationDoesNotWaitForAnotherWindow(t *testing.T) {
	session := &signalledSession{liveSession: newDeliverLive(t, &deliverFake{url: "owned.example.test"}), entered: make(chan struct{})}
	t.Cleanup(func() { _ = session.Close() })
	tools := oobToolsForRun(&ToolSet{}, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := make(chan map[string]any, 1)
	go func() { first <- callOOB(t, tools, "oob_poll", ctx, `{"wait":1}`) }()
	<-session.entered
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	second := make(chan map[string]any, 1)
	go func() { second <- callOOB(t, tools, "oob_generate", cancelled, `{}`) }()
	select {
	case out := <-second:
		if out["status"] != "observation_incomplete" {
			t.Errorf("queued cancellation: %v", out)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("cancelled queued call waited for another observation window")
		cancel()
		<-second
	}
	cancel()
	<-first
}

func TestOOBMissingPollHealthIsIncomplete(t *testing.T) {
	session := &liveSession{it: interactor{client: &deliverFake{url: "owned.example.test"}}}
	defer session.Close()
	tools := oobToolsForRun(&ToolSet{}, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	out := callOOB(t, tools, "oob_poll", t.Context(), `{"wait":1}`)
	if out["status"] != "observation_incomplete" {
		t.Fatalf("missing health must not prove an empty window: %v", out)
	}
}

func TestOOBClosingRunCancelsLazyRegistration(t *testing.T) {
	lazy := newLazySession(oob.Config{})
	entered := make(chan struct{})
	lazy.new = func(ctx context.Context) (*oob.Session, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	tools := oobToolsForRun(&ToolSet{}, lazy)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	generated := make(chan map[string]any, 1)
	go func() { generated <- callOOB(t, tools, "oob_generate", ctx, `{}`) }()
	<-entered
	closed := make(chan struct{})
	go func() { _ = lazy.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Error("closing a run did not cancel in-flight registration")
		cancel()
		<-closed
	}
	if out := <-generated; out["status"] != "observation_incomplete" {
		t.Errorf("closed allocation result: %v", out)
	}
}

type concurrentOOBSource struct {
	mu       sync.Mutex
	next     int
	callback func(oob.Interaction)
	order    []string
}

func (s *concurrentOOBSource) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("owned-%d.example.test", s.next)
}
func (s *concurrentOOBSource) StartPolling(_ time.Duration, cb func(oob.Interaction)) error {
	s.callback = cb
	return nil
}
func (s *concurrentOOBSource) Health() (int64, error, time.Time, time.Time) {
	return 0, nil, time.Time{}, time.Now()
}
func (s *concurrentOOBSource) StopPolling() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, "stop")
	return nil
}
func (s *concurrentOOBSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, "close")
	return nil
}

func TestOOBConcurrentGeneratePollCloseCancellation(t *testing.T) {
	source := &concurrentOOBSource{}
	live, err := newLiveSessionFrom(source, source, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	session := &signalledSession{liveSession: live, entered: make(chan struct{})}
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "concurrent OOB observation"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	tools := oobToolsForRun(worker, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { callOOB(t, tools, "oob_poll", ctx, `{"wait":30}`) })
	<-session.entered
	start := make(chan struct{})
	for i := 0; i < 24; i++ {
		wg.Go(func() {
			<-start
			switch i % 6 {
			case 0, 1:
				callOOB(t, tools, "oob_generate", t.Context(), `{}`)
			case 2:
				callOOB(t, tools, "oob_poll", ctx, `{"wait":30}`)
			case 3:
				source.callback(oob.Interaction{FullID: "owned-1.example.test", Protocol: "dns", Timestamp: time.Unix(123, 456)})
			case 4:
				_ = session.Close()
			case 5:
				cancel()
			}
		})
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent run cleanup did not interrupt bounded polls")
	}
	for _, tool := range []string{"oob_generate", "oob_poll"} {
		if out := callOOB(t, tools, tool, t.Context(), `{}`); out["status"] != "observation_incomplete" {
			t.Errorf("closed %s returned %v", tool, out)
		}
	}
	source.mu.Lock()
	if strings.Join(source.order, ",") != "stop,close" {
		t.Errorf("cleanup order: %v", source.order)
	}
	source.mu.Unlock()
	facts, err := worker.ts.FactsYielded(intentID)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range facts {
		fact, err := worker.ts.GetNode(id)
		if err != nil || fact == nil {
			t.Fatalf("fact %d: %v", id, err)
		}
		var payload map[string]any
		if err := json.Unmarshal(fact.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["outcome"] == "no_interaction" {
			t.Fatalf("cancelled concurrent window became negative fact: %s", fact.Payload)
		}
	}
}

func TestOOBOldCatalogDefaultsKeepLiveOwnership(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "oob_generate" && seed.Key != "oob_poll" {
			continue
		}
		schema, err := json.Marshal(seed.Schema)
		if err != nil {
			t.Fatal(err)
		}
		agents, err := json.Marshal(seed.Agents)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.SeedTool(seed.Key, seed.Desc, schema, agents); err != nil {
			t.Fatal(err)
		}
		// Simulate an existing editable catalog row. Restart seeding must preserve
		// its prose/defaults, but its Call still uses the current ownership handler.
		property, value := "count", 2
		if seed.Key == "oob_poll" {
			property, value = "wait", 1
		}
		seed.Schema["properties"].(map[string]any)[property].(map[string]any)["default"] = value
		customSchema, err := json.Marshal(seed.Schema)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.UpdateTool(seed.Key, "existing "+seed.Desc, customSchema, agents, true); err != nil {
			t.Fatal(err)
		}
		if err := d.SeedTool(seed.Key, seed.Desc, schema, agents); err != nil {
			t.Fatal(err)
		}
	}
	tools := oobToolsForRun(&ToolSet{}, &fakeSession{url: "owned.example.test"})
	for i, tool := range tools {
		row, err := d.GetTool(tool.Name())
		if err != nil || row == nil {
			t.Fatalf("catalog %s: %v", tool.Name(), err)
		}
		if !row.Enabled || !strings.HasPrefix(row.Description, "existing ") || len(row.Agents) != 1 || row.Agents[0] != "worker" {
			t.Fatalf("existing row changed: %+v", row)
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		tools[i] = DecorateTool(tool, row.Description, schema)
	}
	if out := callOOB(t, tools, "oob_poll", t.Context(), `{"probe_id":"old-run"}`); out["status"] != "unknown_probe" {
		t.Fatalf("catalog wrapper bypassed ownership: %v", out)
	}
	if out := callOOB(t, tools, "oob_poll", t.Context(), `{}`); out["status"] != "observation_incomplete" {
		t.Fatalf("unallocated default poll became healthy: %v", out)
	}
	if out := callOOB(t, tools, "oob_generate", t.Context(), `{}`); len(out["probes"].([]any)) != 2 {
		t.Fatalf("old count default lost: %v", out)
	}
	out := callOOB(t, tools, "oob_poll", t.Context(), `{}`)
	observation, _ := out["observation"].(map[string]any)
	if out["status"] != "ok" || observation["requested_wait_ms"] != float64(1000) || observation["complete"] != true {
		t.Fatalf("old wait default not enforced as a complete window: %v", out)
	}
}

func TestOOBPollRejectsPreviousRunProbe(t *testing.T) {
	worker := routeToolSet(t)
	intentID, err := worker.ts.AddIntent(map[string]any{"summary": "observe owned probe"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	runA := oobToolsForRun(worker, &prefixSession{fakeSession: &fakeSession{url: "old.example.test"}, prefix: "old-probe"})
	allocated := callOOB(t, runA, "oob_generate", t.Context(), `{}`)
	oldID := allocated["probes"].([]any)[0].(map[string]any)["probe_id"].(string)
	runB := oobToolsForRun(worker, &prefixSession{fakeSession: &fakeSession{url: "new.example.test"}, prefix: "new-probe"})
	callOOB(t, runB, "oob_generate", t.Context(), `{}`)
	out := callOOB(t, runB, "oob_poll", t.Context(), `{"probe_id":"`+oldID+`","wait":1}`)
	if out["status"] != "unknown_probe" {
		t.Fatalf("previous-run probe must not become a healthy empty observation: %v", out)
	}
	if ids, err := worker.ts.FactsYielded(intentID); err != nil || len(ids) != 0 {
		t.Fatalf("invalid probe must not write an observation: %v %v", ids, err)
	}
}
