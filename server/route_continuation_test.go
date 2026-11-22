package server

import (
	"encoding/json"
	"testing"
)

func TestContinueWorkQueuesForOrdinaryWorkerPool(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("route queue", "continue", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	id, err := task.Store.AddIntent(map[string]any{"summary": "original"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err = task.Store.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	if ok, err := task.Store.PrepareIntentContinuation(id); err != nil || !ok {
		t.Fatalf("prepare: %v %v", ok, err)
	}
	e := NewEngine(m)
	if err = e.ContinueWork(id, "new evidence"); err != nil {
		t.Fatal(err)
	}
	frontier, err := task.Store.Frontier(10)
	if err != nil || len(frontier) != 1 || frontier[0].ID != id {
		t.Fatalf("frontier=%v err=%v", frontier, err)
	}
	var payload map[string]any
	_ = json.Unmarshal(frontier[0].Payload, &payload)
	if payload["continuation_message"] != "new evidence" {
		t.Fatal(payload)
	}
	if e.work[id] != nil {
		t.Fatal("continuation bypassed pool")
	}
}
