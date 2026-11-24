package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/traffic"
)

func TestWorkerReadsPagedTrafficAndHandsOffFactWithoutNewCapture(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { _ = d.Close() })
	task, err := d.CreateTask("traffic handoff", "read captured evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "inspect stored response"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := store.GetNode(intentID)
	if err != nil {
		t.Fatal(err)
	}

	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	const marker = "PAGED-OBSERVATION-TAIL"
	body := strings.Repeat("ordinary captured response ", 190) + marker
	trafficID, err := tr.ImportBrowser(traffic.BrowserExchange{
		URL: "https://fixture.example.test/report", Method: "GET", Status: 200,
		ResponseHeaders: []traffic.ImportHeader{{Name: "Content-Type", Value: "text/plain"}},
		ResponseBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	capturedBefore, err := tr.Count()
	if err != nil || capturedBefore != 1 {
		t.Fatalf("expected one pre-captured exchange, count=%d err=%v", capturedBefore, err)
	}

	provider := &scriptedProvider{}
	provider.add(toolTurn("read-preview", "traffic_get", map[string]any{"id": trafficID})...)
	provider.add(toolTurn("read-page", "traffic_get", map[string]any{
		"id": trafficID, "side": "response", "offset": 5000, "length": 512,
	})...)
	provider.add(toolTurn("handoff", "record_fact", map[string]any{
		"summary": "captured response contains a delayed observation",
		"detail":  "The stored response tail contains " + marker,
		"evidence": "traffic_get paged response: " + marker,
	})...)
	provider.add(textTurn("Stored response evidence was read and handed off.")...)

	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 5, tr.Tools()...)
	if _, _, err := worker.Execute(t.Context(), "worker-traffic", task.ID, nil, store, intent, nil, nil, nil, nil); err != nil {
		t.Fatalf("worker execution failed: %v", err)
	}
	pageReturnedMarker := false
	for _, req := range provider.reqs {
		for _, message := range req.Messages {
			for _, block := range message.Content {
				if block.Type == llm.BlockToolResult {
					for _, content := range block.Content {
						if strings.Contains(content.Text, marker) {
							pageReturnedMarker = true
						}
					}
				}
			}
		}
	}
	if !pageReturnedMarker {
		t.Fatal("worker never received the captured response marker from a traffic_get page")
	}
	capturedAfter, err := tr.Count()
	if err != nil || capturedAfter != capturedBefore {
		t.Fatalf("reading stored evidence changed target capture count: before=%d after=%d err=%v", capturedBefore, capturedAfter, err)
	}

	factIDs, err := store.FactsYielded(intentID)
	if err != nil || len(factIDs) != 1 {
		t.Fatalf("worker did not hand off exactly one fact: ids=%v err=%v", factIDs, err)
	}
	fact, err := store.GetNode(factIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(fact.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload["detail"].(string), marker) || !strings.Contains(payload["evidence"].(string), marker) {
		t.Fatalf("fact did not retain the paged observation: %+v", payload)
	}
}
