package db

import (
	"encoding/json"
	"testing"
)

func TestEndpointArchiveCanonicalReferences(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("endpoint archive", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	candidate, endpoint, err := d.Assets().RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://archive.example/users/1?id=1", Method: "GET", Source: "traffic",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = d.Assets().RecordEndpointObservation(EndpointObservation{TaskID: task.ID, URL: "https://archive.example/pending", Source: "static"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := d.Assets().GetByIDs([]int64{endpoint})
	if err != nil || len(assets) != 1 || assets[0].ServiceID == nil {
		t.Fatalf("endpoint: %v %v", assets, err)
	}
	service := *assets[0].ServiceID
	// Seed an old-format duplicate and two references that must collapse on
	// restore, as happens with packages written before schema 2.
	var duplicate int64
	if err := d.QueryRow(`INSERT INTO assets(type,url,method,task_ids,params) VALUES('endpoint','https://archive.example/users/2?id=2','get',json_array($1),'[{"location":"body","name":"payload"}]') RETURNING id`, task.ID).Scan(&duplicate); err != nil {
		t.Fatal(err)
	}
	node, err := d.Exploration(task.ExplorationID).AddNode(KindFact, map[string]any{"summary": "archive references", "asset_ids": []int64{endpoint, duplicate}}, 1, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{endpoint, duplicate} {
		if err := d.Exploration(task.ExplorationID).Anchor(node, id); err != nil {
			t.Fatal(err)
		}
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["endpoint_candidates"] != 2 {
		t.Errorf("candidates missing from snapshot: %v", snapshot.DataCounts)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "fixture.tar.zst", "fixture", 100, 50); err != nil {
		t.Fatal(err)
	}
	if rows, err := d.Assets().ListEndpointCandidates(task.ID, ""); err != nil || len(rows) != 0 {
		t.Errorf("candidates remain hot: %v %v", rows, err)
	}
	// Reuse the old service ID to make stale foreign keys visible.
	if _, err := d.Exec(`INSERT INTO assets(id,type,domain) VALUES($1,'root_domain','unrelated.example')`, service); err != nil {
		t.Fatal(err)
	}
	hotService, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{
		URL: "https://archive.example", PageTitle: "hot service metadata", Technologies: []string{"hot-tech"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var archivedAssets []map[string]any
	if err := json.Unmarshal(snapshot.Tables["assets"], &archivedAssets); err != nil {
		t.Fatal(err)
	}
	for _, row := range archivedAssets {
		if row["type"] == "service" && row["service_type"] == "http" {
			row["url"] = "https://archive.example:443"
			row["page_title"] = "archived service metadata"
			row["technologies"] = []any{"archive-tech"}
		}
	}
	snapshot.Tables["assets"], err = json.Marshal(archivedAssets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Assets().ListEndpointCandidates(task.ID, "")
	if err != nil || len(rows) != 2 {
		t.Fatalf("restored candidates: %v %v", rows, err)
	}
	var restored *EndpointCandidate
	for _, row := range rows {
		if row.ID == candidate {
			restored = row
		}
	}
	if restored == nil || restored.AssetID == 0 || restored.Status != "confirmed" {
		t.Fatalf("lost confirmed link: %+v", restored)
	}
	assets, err = d.Assets().GetByIDs([]int64{restored.AssetID})
	if err != nil || len(assets) != 1 {
		t.Fatalf("asset: %v %v", assets, err)
	}
	a := assets[0]
	if a.ServiceID == nil || *a.ServiceID != hotService || a.URL != "https://archive.example/users/{id}" {
		t.Fatalf("stale endpoint identity/owner: %+v", a)
	}
	var serviceCount, technologyCount int
	if err := d.QueryRow(`SELECT count(*),max(json_array_length(technologies)) FROM assets WHERE type='service' AND service_type='http' AND url='https://archive.example'`).Scan(&serviceCount, &technologyCount); err != nil || serviceCount != 1 || technologyCount != 2 {
		t.Fatalf("archive duplicated service or lost metadata: count=%d technologies=%d err=%v", serviceCount, technologyCount, err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, node, a.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("anchors: %d %v", count, err)
	}
	var raw []byte
	if err := d.QueryRow(`SELECT payload FROM exploration_nodes WHERE id=$1`, node).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || len(payload.AssetIDs) != 1 || payload.AssetIDs[0] != a.ID {
		t.Fatalf("payload refs: %s %v", raw, err)
	}
	found := false
	for _, param := range a.Params {
		found = found || param["name"] == "payload"
	}
	if !found {
		t.Fatalf("duplicate params lost: %+v", a.Params)
	}
}
