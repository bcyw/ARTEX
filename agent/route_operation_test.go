package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/db"
)

func operationTool(t *testing.T, tools []actool.CoreTool, name string, input any) actool.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		if tool.Name() == name {
			out, err := tool.Call(t.Context(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
	}
	t.Fatalf("tool %s not registered", name)
	return actool.Result{}
}

type operationOverview struct {
	Routes []struct {
		ID            string `json:"id"`
		Method        string `json:"method"`
		InputLocation string `json:"input_location"`
		Intents       int    `json:"intents"`
		Stopped       bool   `json:"stopped"`
	} `json:"routes"`
}

func readOperations(t *testing.T, tools *ToolSet) operationOverview {
	t.Helper()
	out := operationTool(t, tools.PlannerTools(), "graph_overview", map[string]any{})
	var overview operationOverview
	if err := json.Unmarshal([]byte(out.Flatten()), &overview); err != nil || out.IsError {
		t.Fatalf("overview: %s (%v)", out.Flatten(), err)
	}
	return overview
}

func TestOperationSelectorsRemainDistinctWithinSharedBudget(t *testing.T) {
	tools := intentTypeToolSet(t)
	operations := []struct{ method, selector string }{
		{"GET", "query:id"},
		{"POST", "body:id"},
		{"POST", "body:user.id"},
		{"POST", "body:userid"},
		{"POST", "body:user.Id"},
		{"GET", "query:action=preview;query:id"},
	}
	for i, op := range operations {
		out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
			"summary": fmt.Sprintf("operation %d", i),
			"route":   map[string]any{"entry": "https://example.test/item?action=preview", "family": "query", "method": op.method, "input_location": op.selector},
		})
		if out.IsError {
			t.Fatalf("operation %+v was conflated: %s", op, out.Flatten())
		}
	}
	rows := readOperations(t, tools).Routes
	if len(rows) != 6 {
		t.Fatalf("want six operation states, got %+v", rows)
	}
	ids := map[string]bool{}
	for _, op := range operations {
		found := false
		for _, row := range rows {
			if row.Method == op.method && row.InputLocation == op.selector {
				if ids[row.ID] || row.Intents != 1 {
					t.Fatalf("operation reused identity or count: %+v", row)
				}
				ids[row.ID], found = true, true
			}
		}
		if !found {
			t.Fatalf("missing operation %+v in %+v", op, rows)
		}
	}
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "a renamed operation cannot create more budget",
		"route":   map[string]any{"entry": "https://example.test/item?action=commit", "family": "query", "method": "PATCH", "component": "another component", "parameter": "other", "input_location": "query:action=commit;body:id"},
	})
	if !out.IsError {
		t.Fatal("seventh operation bypassed the shared six-attempt cap")
	}
}

func TestOperationHandoffKeepsWorkerAndPlannerContext(t *testing.T) {
	for _, tc := range []struct{ entry, method, selector string }{
		{"https://example.test/import", "POST", "body:document.expression"},
		{"tcp://fixture.test:9000", "", "protocol:IMPORT record[0].Expression"},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": tc.entry, "family": "parser", "method": tc.method, "input_location": tc.selector}
			out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "read the assigned operation", "route": route})
			if out.IsError {
				t.Fatal(out.Flatten())
			}
			intent, err := tools.ts.GetNode(parseCreatedIntentID(t, out.Flatten()))
			if err != nil {
				t.Fatal(err)
			}
			provider := &scriptedProvider{}
			provider.add(toolTurn("handoff", "record_fact", map[string]any{
				"summary": "operation context is available; observation remains planned",
				// An older worker can repeat the route without the new optional fields.
				"route":      map[string]any{"entry": tc.entry, "family": "parser"},
				"experiment": map[string]any{"method": tc.method, "input_location": tc.selector, "execution_state": "planned"},
			})...)
			provider.add(textTurn("handoff saved")...)
			taskID, _ := tools.ts.TaskID()
			worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 3)
			if _, _, err := worker.Execute(t.Context(), "operation-worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			if len(provider.reqs) == 0 || !strings.Contains(strings.Join(provider.reqs[0].System, "\n"), tc.selector) {
				t.Fatal("worker's own assembled input lost the assigned operation")
			}
			rows := readOperations(t, tools).Routes
			if len(rows) != 1 || rows[0].Method != tc.method || rows[0].InputLocation != tc.selector {
				t.Fatalf("fact split or changed operation identity: %+v", rows)
			}
			facts, err := tools.ts.ListByKind(db.KindFact, 10)
			if err != nil || len(facts) == 0 {
				t.Fatal("fact missing", err)
			}
			detail := operationTool(t, tools.PlannerTools(), "node_detail", map[string]any{"id": facts[0].ID})
			if detail.IsError || !strings.Contains(detail.Flatten(), tc.selector) {
				t.Fatalf("experiment cannot be recovered: %s", detail.Flatten())
			}
		})
	}
}

func TestOperationRefinementPreservesLegacyStop(t *testing.T) {
	tools := intentTypeToolSet(t)
	base := map[string]any{"entry": "https://example.test/item", "family": "query"}
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "legacy operation", "route": base})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	id := parseCreatedIntentID(t, created.Flatten())
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(id)
	stop := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{
		"summary": "legacy route completed", "outcome": "negative", "confidence": "observed", "evidence": "controlled normal and variant responses match",
	})
	if stop.IsError {
		t.Fatal(stop.Flatten())
	}
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "refined name does not erase previous stop",
		"route":   map[string]any{"entry": base["entry"], "family": base["family"], "method": "POST", "input_location": "body:other", "component": "renamed"},
	})
	if !out.IsError || !strings.Contains(out.Flatten(), "停止") {
		t.Fatalf("legacy stop was lost on operation refinement: %s", out.Flatten())
	}
}

func TestOperationFactDoesNotInheritIntentConclusion(t *testing.T) {
	for _, fullRoute := range []bool{false, true} {
		t.Run(fmt.Sprintf("full fact route=%t", fullRoute), func(t *testing.T) {
			tools := intentTypeToolSet(t)
			base := map[string]any{"entry": "https://example.test/legacy-conclusion", "family": "parser"}
			id, err := tools.ts.AddIntent(map[string]any{
				"summary": "historical intent with an unsupported conclusion",
				"route":   map[string]any{"entry": base["entry"], "family": base["family"], "outcome": "impact", "method": "POST", "input_location": "body:id"},
			}, 5, nil, "planner")
			if err != nil {
				t.Fatal(err)
			}
			worker := NewToolSet(tools.ts, "worker")
			worker.SetOwnerNode(id)
			fact := map[string]any{"summary": "only the operation was recovered; no conclusion yet"}
			if fullRoute {
				fact["route"] = base
			}
			out := operationTool(t, worker.WorkerTools(), "record_fact", fact)
			if out.IsError {
				t.Fatal(out.Flatten())
			}
			rows := readOperations(t, tools).Routes
			if len(rows) != 1 || rows[0].Stopped || rows[0].Method != "POST" || rows[0].InputLocation != "body:id" {
				t.Fatalf("operation recovery invented a fact conclusion or lost identity: %+v", rows)
			}
		})
	}
}

func TestOperationRefinementDoesNotPromoteUnsupportedLegacyStops(t *testing.T) {
	for _, outcome := range []string{"impact", "prerequisite_disproved", "variants_exhausted", "negative"} {
		for _, tc := range []struct {
			name, confidence, evidence string
			wantStop                   bool
		}{
			{"no observation or evidence", "", "", false},
			{"observation without evidence", "observed", "", false},
			{"evidence without observation", "", "fixture response: control=variant", false},
			{"inferred conclusion", "inferred", "fixture response: control=variant", false},
			{"supported observation", "observed", "fixture response: control=variant", true},
		} {
			t.Run(outcome+"/"+tc.name, func(t *testing.T) {
				tools := intentTypeToolSet(t)
				base := map[string]any{"entry": "https://example.test/historical-stop", "family": "parser"}
				created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "historical operation", "route": base})
				if created.IsError {
					t.Fatal(created.Flatten())
				}
				intentID := parseCreatedIntentID(t, created.Flatten())
				// Pre-upgrade facts can contain conclusions with no observed basis.
				factID, err := tools.ts.AddNode(db.KindFact, map[string]any{
					"summary": "historical conclusion", "outcome": outcome,
					"confidence": tc.confidence, "evidence": tc.evidence,
				}, 5, "confirmed", "worker", nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := tools.ts.Link(intentID, db.RelYields, factID); err != nil {
					t.Fatal(err)
				}
				fresh, err := tools.ts.AddNode(db.KindFact, map[string]any{
					"summary": "new discriminator", "confidence": "observed", "evidence": "fixture response: new input handler selected",
				}, 5, "confirmed", "worker", nil)
				if err != nil {
					t.Fatal(err)
				}
				out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
					"summary": "refine with a new observation", "parent_ids": []int64{fresh},
					"route": map[string]any{"entry": base["entry"], "family": base["family"], "method": "POST", "input_location": "body:id"},
				})
				if tc.wantStop {
					if !out.IsError || !strings.Contains(out.Flatten(), "停止") {
						t.Fatalf("supported historical stop lost its scope: %s", out.Flatten())
					}
				} else if out.IsError {
					t.Fatalf("unsupported legacy conclusion gained stop authority: %s", out.Flatten())
				}
			})
		}
	}
}

func TestOperationLegacyMethodRecoveryIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name, entry, want string
		methods           []string
	}{
		{"one anchored method", "https://example.test/item", "POST", []string{"POST"}},
		{"conflicting anchored methods", "https://example.test/item", "", []string{"POST", "GET"}},
		{"no method evidence", "https://example.test/item", "", nil},
		{"non HTTP context", "tcp://example.test:9000", "", []string{"POST"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			var anchors []int64
			for _, method := range tc.methods {
				id, err := tools.ts.DB().Assets().UpsertEndpoint(db.UpsertEndpointReq{URL: tc.entry, Method: method, TaskID: tools.taskID})
				if err != nil {
					t.Fatal(err)
				}
				anchors = append(anchors, id)
			}
			// A persisted pre-upgrade route has neither optional operation field.
			_, err := tools.ts.AddIntent(map[string]any{"summary": "legacy intent", "route": map[string]any{"entry": tc.entry, "family": "parser"}}, 5, anchors, "planner")
			if err != nil {
				t.Fatal(err)
			}
			rows := readOperations(t, tools).Routes
			if len(rows) != 1 || rows[0].Method != tc.want || rows[0].InputLocation != "" || rows[0].Intents != 1 {
				t.Fatalf("legacy recovery fabricated or lost operation context: %+v", rows)
			}
		})
	}
}

func TestOperationRefinementHonorsExecutionControls(t *testing.T) {
	for _, control := range []string{"manual stop", "task paused"} {
		t.Run(control, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": "https://example.test/controlled", "family": "parser"}
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "controlled operation", "route": route})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			id := parseCreatedIntentID(t, created.Flatten())
			if control == "manual stop" {
				if err := tools.ts.SetIntentState(id, "stopped"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := tools.ts.DB().SetPaused(tools.taskID, true); err != nil {
					t.Fatal(err)
				}
				// Task controls also apply before a route has any historical state.
				route["entry"] = "https://example.test/another"
			}
			route["method"], route["input_location"] = "POST", "body:new"
			out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "refined operation", "route": route})
			if !out.IsError {
				t.Fatalf("operation refinement bypassed %s: %s", control, out.Flatten())
			}
		})
	}
}

func TestOperationWhitespaceCannotBypassManualStop(t *testing.T) {
	for _, op := range []struct{ method, selector string }{
		{" ", "body:id"},
		{"POST", " \t"},
		{" \n", " \t"},
	} {
		t.Run(fmt.Sprintf("%q/%q", op.method, op.selector), func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{"entry": "https://example.test/stopped", "family": "parser", "method": "POST", "input_location": "body:id"}
			created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "stopped operation", "route": route})
			if created.IsError {
				t.Fatal(created.Flatten())
			}
			if err := tools.ts.SetIntentState(parseCreatedIntentID(t, created.Flatten()), "stopped"); err != nil {
				t.Fatal(err)
			}
			route["method"], route["input_location"] = op.method, op.selector
			out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "unknown scope after trimming", "route": route})
			if !out.IsError || !strings.Contains(out.Flatten(), "停止") {
				t.Fatalf("whitespace bypassed stopped operation: %s", out.Flatten())
			}
		})
	}
}

func TestOperationRefinementKeepsLegacyConsumptionAfterReopen(t *testing.T) {
	for _, anchoredMethod := range []bool{false, true} {
		t.Run(fmt.Sprintf("anchored method=%t", anchoredMethod), func(t *testing.T) {
			checkOperationLegacyConsumptionAfterReopen(t, anchoredMethod)
		})
	}
}

func checkOperationLegacyConsumptionAfterReopen(t *testing.T, anchoredMethod bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy-consumption.sqlite")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("legacy consumption", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	base := map[string]any{"entry": "https://example.test/consumed", "family": "parser"}
	var anchors []int64
	if anchoredMethod {
		assetID, err := d.Assets().UpsertEndpoint(db.UpsertEndpointReq{URL: base["entry"].(string), Method: "POST", TaskID: task.ID})
		if err != nil {
			t.Fatal(err)
		}
		anchors = []int64{assetID}
	}
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "old operation", "route": base, "asset_ids": anchors})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	id := parseCreatedIntentID(t, created.Flatten())
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(id)
	result := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{"summary": "saved control response", "confidence": "observed", "evidence": "control response token=legacy"})
	if result.IsError {
		t.Fatal(result.Flatten())
	}
	facts, err := tools.ts.FactsYielded(id)
	if err != nil || len(facts) != 1 {
		t.Fatalf("facts: %v %v", facts, err)
	}
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	tools.SetContinueWork(func(int64, string) error { return nil })
	continued := operationTool(t, tools.PlannerTools(), "continue_intent", map[string]any{"intent_id": id, "message": "follow saved control", "parent_ids": facts})
	if continued.IsError {
		t.Fatal(continued.Flatten())
	}
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{}
	for i := 0; i < 3; i++ {
		provider.add(textTurn("No new evidence.")...)
	}
	planner := NewPlanner(provider, "test-model", t.TempDir(), nil, 0, 2)
	for i := 0; i < 3; i++ {
		if _, _, err := planner.Plan(t.Context(), task.ID, nil, tools.ts, task.Goal, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tools = NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	base["method"] = "POST"
	if anchoredMethod {
		rows := readOperations(t, tools).Routes
		if len(rows) != 1 || rows[0].Method != "POST" || rows[0].InputLocation != "" {
			t.Fatalf("legacy method display was not recovered: %+v", rows)
		}
	} else {
		base["input_location"] = "body:id"
	}
	for _, parents := range [][]int64{facts, nil} {
		out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "refine saved operation", "route": base, "parent_ids": parents})
		want := "信息"
		if len(parents) == 0 {
			want = "连续 3 轮"
		}
		if !out.IsError || !strings.Contains(out.Flatten(), want) {
			t.Errorf("refinement lost consumed evidence/information-free history (parents=%v): %s", parents, out.Flatten())
		}
	}
	// New evidence remains usable; conservative recovery must not ban refinement.
	fresh, err := tools.ts.AddNode(db.KindFact, map[string]any{"summary": "new control response", "confidence": "observed", "evidence": "control response token=fresh"}, 5, "confirmed", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "refine with new observation", "route": base, "parent_ids": []int64{fresh}})
	if out.IsError {
		t.Fatalf("new evidence was rejected after recovery: %s", out.Flatten())
	}
}

func TestOperationContinuationCannotIncreaseSharedCapAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.sqlite")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("operation budget", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	route := map[string]any{"entry": "https://example.test/continue", "family": "parser", "method": "POST", "input_location": "body:user.id"}
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "first operation", "route": route, "route_cap": 2})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	id := parseCreatedIntentID(t, created.Flatten())
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(id)
	result := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{"summary": "parser response", "confidence": "observed", "evidence": "parser rejected the control at byte 12"})
	if result.IsError {
		t.Fatal(result.Flatten())
	}
	facts, err := tools.ts.FactsYielded(id)
	if err != nil || len(facts) != 1 {
		t.Fatalf("handoff: %v %v", facts, err)
	}
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	tools.SetContinueWork(func(int64, string) error { return nil })
	continued := operationTool(t, tools.PlannerTools(), "continue_intent", map[string]any{"intent_id": id, "message": "follow the parser observation", "parent_ids": facts, "route_cap": 100})
	if continued.IsError {
		t.Fatal(continued.Flatten())
	}
	before := readOperations(t, tools).Routes
	if len(before) != 1 || before[0].Intents != 2 {
		t.Fatalf("original intent rerun did not charge the shared budget: %+v", before)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	tools = NewToolSet(d.Exploration(task.ExplorationID), "planner")
	tools.SetTaskID(task.ID)
	after := readOperations(t, tools).Routes
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("reopen changed operation identity/budget: %+v -> %+v", before, after)
	}
	route["method"], route["input_location"] = "GET", "query:id"
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "refine after restart", "route": route, "route_cap": 100})
	if !out.IsError || !strings.Contains(out.Flatten(), "共享上限") {
		t.Fatalf("continuation/refinement increased persisted two-attempt cap: %s", out.Flatten())
	}
}

func TestOperationConcurrentAdmissionSharesLegacyAndRerunBudget(t *testing.T) {
	tools := intentTypeToolSet(t)
	entry := "https://example.test/concurrent"
	legacyID, err := tools.ts.AddIntent(map[string]any{
		"summary": "legacy executions", "route_runs": 2,
		"route": map[string]any{"entry": entry, "family": "parser"},
	}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	legacyWorker := NewToolSet(tools.ts, "worker")
	legacyWorker.SetOwnerNode(legacyID)
	observed := operationTool(t, legacyWorker.WorkerTools(), "record_fact", map[string]any{"summary": "operation discriminator observed", "confidence": "observed", "evidence": "fixture selector maps to the POST body handler"})
	if observed.IsError {
		t.Fatal(observed.Flatten())
	}
	legacyFacts, err := tools.ts.FactsYielded(legacyID)
	if err != nil || len(legacyFacts) != 1 {
		t.Fatalf("legacy handoff: %v %v", legacyFacts, err)
	}
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "current operation", "parent_ids": legacyFacts, "route": map[string]any{"entry": entry, "family": "parser", "method": "POST", "input_location": "body:id"},
	})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	id := parseCreatedIntentID(t, created.Flatten())
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(id)
	result := operationTool(t, worker.WorkerTools(), "record_fact", map[string]any{"summary": "observed input handler", "confidence": "observed", "evidence": "fixture parser state: type=text"})
	if result.IsError {
		t.Fatal(result.Flatten())
	}
	facts, err := tools.ts.FactsYielded(id)
	if err != nil || len(facts) != 1 {
		t.Fatalf("handoff: %v %v", facts, err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			planner := NewToolSet(tools.ts, "planner")
			planner.SetTaskID(tools.taskID)
			planner.SetContinueWork(func(int64, string) error { return nil })
			name := "add_intent"
			input := map[string]any{"summary": "refinement", "parent_ids": facts, "route_cap": 100, "route": map[string]any{"entry": entry, "family": "parser", "method": "GET", "input_location": fmt.Sprintf("query:item[%d]", i)}}
			if i == 0 {
				name, input = "continue_intent", map[string]any{"intent_id": id, "message": "follow observation", "parent_ids": facts, "route_cap": 100}
			}
			if !operationTool(t, planner.PlannerTools(), name, input).IsError {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatalf("legacy two runs + current run leave three slots, accepted %d", accepted.Load())
	}
	total := 0
	for _, row := range readOperations(t, tools).Routes {
		total += row.Intents
	}
	if total != 6 {
		t.Fatalf("concurrent operations lost or duplicated charges: %d", total)
	}
}

func TestOperationImplicitBudgetHonorsLoweredRuntimeLimit(t *testing.T) {
	oldCap := RouteCapOverride
	limit := 6
	SetRouteCapResolver(func() int { return limit })
	t.Cleanup(func() { SetRouteCapResolver(oldCap) })
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/runtime-cap", "family": "parser", "method": "POST", "input_location": "body:id"}
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "initial operation", "route": route})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	limit = 1
	route["input_location"] = "body:other"
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "runtime ceiling lowered", "route": route})
	if !out.IsError || !strings.Contains(out.Flatten(), "共享上限") {
		t.Fatalf("operation identity pinned an implicit budget above the runtime limit: %s", out.Flatten())
	}
}

func TestOperationLegacyRecoveryRetainsLowestExplicitCeiling(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/old-caps", "family": "parser"}
	for _, cap := range []int{2, 100} {
		if _, err := tools.ts.AddIntent(map[string]any{"summary": "legacy attempt", "route": route, "route_cap": cap}, 5, nil, "planner"); err != nil {
			t.Fatal(err)
		}
	}
	route["method"], route["input_location"] = "POST", "body:id"
	out := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "new operation", "route": route})
	if !out.IsError || !strings.Contains(out.Flatten(), "共享上限") {
		t.Fatalf("legacy recovery relaxed the earliest explicit cap: %s", out.Flatten())
	}
}

func TestOperationSummaryIsBoundedAndDetailsStayRetrievable(t *testing.T) {
	tools := intentTypeToolSet(t)
	selector := "body:" + strings.Repeat("层级.", 200) + "Value"
	created := operationTool(t, tools.PlannerTools(), "add_intent", map[string]any{
		"summary": "large operation context",
		"route":   map[string]any{"entry": "https://example.test/nested", "family": "parser", "method": "POST", "input_location": selector},
	})
	if created.IsError {
		t.Fatal(created.Flatten())
	}
	rows := readOperations(t, tools).Routes
	if len(rows) != 1 || len([]rune(rows[0].InputLocation)) > 241 || !strings.HasSuffix(rows[0].InputLocation, "…") {
		t.Fatalf("operation summary is not bounded: %+v", rows)
	}
	detail := operationTool(t, tools.PlannerTools(), "node_detail", map[string]any{"id": parseCreatedIntentID(t, created.Flatten())})
	if detail.IsError || !strings.Contains(detail.Flatten(), selector) {
		t.Fatalf("full operation context was lost: %s", detail.Flatten())
	}
}
