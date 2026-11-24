package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/db"
)

func recordFactTestStore(t *testing.T) (*db.DB, *db.ExplorationStore) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "facts.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	id, err := d.CreateExploration("text fixture", "record a note")
	if err != nil {
		t.Fatal(err)
	}
	return d, d.Exploration(id)
}

func recordFactTestIntent(t *testing.T, store *db.ExplorationStore, summary string) int64 {
	t.Helper()
	id, err := store.AddIntent(map[string]any{"summary": summary}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func callRecordFact(t *testing.T, tools []actool.CoreTool, input string) actool.Result {
	t.Helper()
	for _, tool := range tools {
		if tool.Name() == "record_fact" {
			result, err := tool.Call(t.Context(), json.RawMessage(input), nil)
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	t.Fatal("record_fact not registered")
	return actool.Result{}
}

type recordedFactBatch struct {
	IDs    []int64           `json:"ids"`
	Errors map[string]string `json:"errors"`
}

func callRecordFactBatch(t *testing.T, tools []actool.CoreTool, input string, count int) recordedFactBatch {
	t.Helper()
	result := callRecordFact(t, tools, input)
	var batch recordedFactBatch
	if err := json.Unmarshal([]byte(result.Flatten()), &batch); err != nil || result.IsError || len(batch.IDs) != count {
		t.Fatalf("unexpected batch response: %s (decode: %v)", result.Flatten(), err)
	}
	return batch
}

func TestRecordFactRejectsOtherWorkerIntent(t *testing.T) {
	_, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "first note")
	other := recordFactTestIntent(t, store, "second note")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(owner)
	tools := worker.WorkerTools()
	input := fmt.Sprintf(`{"summary":"unrelated note","intent_id":%d}`, other)

	if result := callRecordFact(t, tools, input); !result.IsError || !strings.Contains(result.Flatten(), "intent_id") {
		t.Errorf("record_fact did not reject an unrelated intent: %s", result.Flatten())
	}
	if err := store.DiscardOpenIntent(owner); err != nil {
		t.Fatal(err)
	}
	if result := callRecordFact(t, tools, input); !result.IsError || !strings.Contains(result.Flatten(), "intent_id") {
		t.Errorf("removing the assigned intent allowed a write to an unrelated intent: %s", result.Flatten())
	}
	facts, err := store.ListByKind(db.KindFact, 10)
	if err != nil || len(facts) != 0 {
		t.Errorf("rejected note changed the task graph: %d facts, err=%v", len(facts), err)
	}
	if written := worker.Writes().Facts; written != 0 {
		t.Errorf("rejected note counted as written: %d", written)
	}
}

func TestRecordFactRejectsInvalidIntentID(t *testing.T) {
	_, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "first note")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(owner)
	tools := worker.WorkerTools()
	for _, tc := range []struct{ name, value string }{
		{"null", `null`},
		{"zero", `0`},
		{"negative", `-1`},
		{"fraction", `1.5`},
		{"boolean", `true`},
		{"object", `{}`},
		{"array", `[]`},
		{"empty string", `""`},
		{"nonnumeric string", `"not an ID"`},
		{"overflow", `9223372036854775808`},
		{"overflow string", `"9223372036854775808"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := callRecordFact(t, tools, fmt.Sprintf(`{"summary":"sample note","intent_id":%s}`, tc.value))
			if !result.IsError || !strings.Contains(result.Flatten(), "intent_id") {
				t.Errorf("invalid intent_id was accepted: %s", result.Flatten())
			}
		})
	}
	facts, err := store.ListByKind(db.KindFact, 20)
	if err != nil || len(facts) != 0 {
		t.Errorf("invalid intent_id changed the task graph: %d facts, err=%v", len(facts), err)
	}
}

func TestRecordFactRejectsOutOfScopeIntent(t *testing.T) {
	d, store := recordFactTestStore(t)
	foreign, err := d.CreateExploration("another text fixture", "record a different note")
	if err != nil {
		t.Fatal(err)
	}
	foreignStore := d.Exploration(foreign)
	foreignIntent := recordFactTestIntent(t, foreignStore, "sort other notes")
	localGoal, err := store.AddGoal(map[string]any{"summary": "organize notes"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "main").MainAgentTools()
	for _, id := range []int64{foreignIntent, localGoal} {
		if result := callRecordFact(t, tools, fmt.Sprintf(`{"summary":"sample note","intent_id":%d}`, id)); !result.IsError || !strings.Contains(result.Flatten(), "intent_id") {
			t.Errorf("record_fact accepted out-of-scope intent %d: %s", id, result.Flatten())
		}
	}
	for _, s := range []*db.ExplorationStore{store, foreignStore} {
		if facts, err := s.ListByKind(db.KindFact, 10); err != nil || len(facts) != 0 {
			t.Errorf("rejected note changed task %d: %d facts, err=%v", s.ID(), len(facts), err)
		}
	}
}

func TestRecordFactPreservesSingleWriteOwnership(t *testing.T) {
	_, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "collect notes")
	other := recordFactTestIntent(t, store, "sort notes")
	origin, err := store.AddNode(db.KindFact, map[string]any{"summary": "notebook"}, 0, "origin", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(owner)
	main := NewToolSet(store, "main")
	main.SetOwnerNode(origin)
	for _, tc := range []struct {
		name       string
		tools      []actool.CoreTool
		input      string
		wantIntent int64
	}{
		{"omitted by worker defaults to current intent", worker.WorkerTools(), `{"summary":"loose note"}`, owner},
		{"worker with numeric string", worker.WorkerTools(), fmt.Sprintf(`{"summary":"collected note","intent_id":" %d "}`, owner), owner},
		{"no owner node", NewToolSet(store, "main").MainAgentTools(), fmt.Sprintf(`{"summary":"sorted note","intent_id":%d}`, other), other},
		{"origin fact is not a worker intent", main.MainAgentTools(), fmt.Sprintf(`{"summary":"another sorted note","intent_id":%d}`, other), other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := callRecordFact(t, tc.tools, tc.input)
			rawID, ok := strings.CutPrefix(result.Flatten(), "fact recorded: ")
			id, err := strconv.ParseInt(rawID, 10, 64)
			if result.IsError || !ok || err != nil || id <= 0 {
				t.Fatalf("single response changed: %s", result.Flatten())
			}
			if fact, err := store.GetNode(id); err != nil || fact == nil || fact.Kind != db.KindFact {
				t.Fatalf("single response did not identify a persisted fact: node=%+v err=%v", fact, err)
			}
			for _, intent := range []int64{owner, other} {
				yielded, err := store.FactsYielded(intent)
				want := intent == tc.wantIntent
				if err != nil || slices.Contains(yielded, id) != want {
					t.Errorf("intent %d yielded %v, %v; fact %d should be linked: %v", intent, yielded, err, id, want)
				}
			}
		})
	}
}

func TestRecordFactBatchDefaultsOnlyOmittedIDs(t *testing.T) {
	_, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "collect notes")
	other := recordFactTestIntent(t, store, "sort notes")
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(owner)
	tools := worker.WorkerTools()
	withDefault := callRecordFactBatch(t, tools, fmt.Sprintf(`{"intent_id":%d,"facts":[
		{"summary":"first note"},
		{"summary":"invalid note","intent_id":null},
		{"summary":"unrelated note","intent_id":%d},
		{"summary":"last note"}
	]}`, owner, other), 4)
	if withDefault.IDs[0] <= 0 || withDefault.IDs[1] != 0 || withDefault.IDs[2] != 0 || withDefault.IDs[3] <= 0 ||
		len(withDefault.Errors) != 2 || !strings.Contains(withDefault.Errors["1"], "intent_id") || !strings.Contains(withDefault.Errors["2"], "intent_id") {
		t.Errorf("invalid explicit IDs were treated as omitted: %+v", withDefault)
	}
	invalidDefault := callRecordFactBatch(t, tools, fmt.Sprintf(`{"intent_id":null,"facts":[
		{"summary":"invalid note"},
		{"summary":"explicit note","intent_id":%d}
	]}`, owner), 2)
	if invalidDefault.IDs[0] != 0 || invalidDefault.IDs[1] <= 0 || len(invalidDefault.Errors) != 1 || !strings.Contains(invalidDefault.Errors["0"], "intent_id") {
		t.Errorf("invalid default should fail only the item using it: %+v", invalidDefault)
	}
	noDefault := callRecordFactBatch(t, tools, `{"facts":[{"summary":"loose note"}]}`, 1)
	if noDefault.IDs[0] <= 0 || len(noDefault.Errors) != 0 {
		t.Errorf("fully omitted IDs should default to the current worker intent: %+v", noDefault)
	}
	want := []int64{withDefault.IDs[0], withDefault.IDs[3], invalidDefault.IDs[1], noDefault.IDs[0]}
	if yielded, err := store.FactsYielded(owner); err != nil || !slices.Equal(yielded, want) {
		t.Errorf("yielded facts = %v, %v; want %v", yielded, err, want)
	}
	if facts, err := store.ListByKind(db.KindFact, 10); err != nil || len(facts) != 4 {
		t.Errorf("expected only successful batch items to persist: %d facts, err=%v", len(facts), err)
	}
}

func TestRecordFactRollsBackPartialWrites(t *testing.T) {
	d, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "collect notes")
	asset, err := d.Assets().UpsertApp(db.UpsertAppReq{Name: "sample notebook"})
	if err != nil {
		t.Fatal(err)
	}
	// Inject a storage failure after the fact and its anchor have been inserted.
	if _, err := d.Exec(`CREATE TRIGGER reject_sample_yields BEFORE INSERT ON exploration_edges
WHEN NEW.rel='yields' AND json_extract((SELECT payload FROM exploration_nodes WHERE id=NEW.dst_id), '$.summary')='rejected note'
BEGIN SELECT RAISE(ABORT, 'fixture yields failed'); END`); err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(store, "worker")
	worker.SetOwnerNode(owner)
	batch := callRecordFactBatch(t, worker.WorkerTools(), fmt.Sprintf(`{"intent_id":%d,"facts":[
		{"summary":"first note","asset_ids":[%d]},
		{"summary":"note with a missing asset","asset_ids":[%d,%d]},
		{"summary":"rejected note","asset_ids":[%d]},
		{"summary":"third note","asset_ids":[%d]}
	]}`, owner, asset, asset, asset+1, asset, asset), 4)
	if batch.IDs[0] <= 0 || batch.IDs[1] != 0 || batch.IDs[2] != 0 || batch.IDs[3] <= 0 ||
		len(batch.Errors) != 2 || !strings.Contains(batch.Errors["1"], "FOREIGN KEY constraint failed") || !strings.Contains(batch.Errors["2"], "fixture yields failed") {
		t.Errorf("batch should preserve successes around the failed writes: %+v", batch)
	}
	facts, err := store.ListByKind(db.KindFact, 10)
	if err != nil || len(facts) != 2 {
		t.Errorf("record_fact committed a partial fact: %d facts, err=%v", len(facts), err)
	}
	want := []int64{batch.IDs[0], batch.IDs[3]}
	if yielded, err := store.FactsYielded(owner); err != nil || !slices.Equal(yielded, want) {
		t.Errorf("yielded facts = %v, %v; want %v", yielded, err, want)
	}
	anchors, err := store.NodeAssets(want)
	if err != nil || !slices.Equal(anchors[want[0]], []int64{asset}) || !slices.Equal(anchors[want[1]], []int64{asset}) {
		t.Errorf("successful facts did not commit both anchors: %v, %v", anchors, err)
	}
	if written := worker.Writes().Facts; written != 2 {
		t.Errorf("expected only committed facts to be counted, got %d", written)
	}
}
