package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// addTypedFinding builds a complete fixture: an exploration finding node plus its
// standalone findings row (the status truth), so the distribution must cross-check
// both like production does. status empty means leave the row at its default.
func addTypedFinding(t *testing.T, d *db.DB, store *db.ExplorationStore, taskID int64, vulnclass, status string) {
	t.Helper()
	nodeID, err := store.AddNode(db.KindFinding, map[string]any{
		"summary": "fixture " + vulnclass, "vulnclass": vulnclass, "severity": "high",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	rowID, err := d.AddFinding(taskID, nodeID, vulnclass, "n", "high", "fixture "+vulnclass, "e", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	switch status {
	case "":
	case db.FindingQuarantined, db.FindingFalsePositive, db.FindingDuplicate, db.FindingIgnored, db.FindingConfirmed:
		if _, err := d.SetFindingStatus(rowID, status); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported fixture status: %q", status)
	}
}

// TestGraphOverviewFindingTypeCounts pins ticket 03: the planner's situational
// overview carries a per-canonical-bucket finding count (alias variants folded
// into one bucket, unknown vulnclasses keep their own), quarantined /
// false_positive / duplicate / ignored rows are excluded, and the current
// per-type cap rides along so the planner can see which buckets are full.
func TestGraphOverviewFindingTypeCounts(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("type counts", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	// Two alias spellings of the same class fold into one bucket; one valid
	// finding per two other classes; one quarantined, one false_positive, one
	// duplicate and one ignored finding must not count; one unknown class
	// becomes its own bucket instead of being dropped.
	addTypedFinding(t, d, store, task.ID, "sql_injection", "")
	addTypedFinding(t, d, store, task.ID, "SQL 注入", db.FindingConfirmed)
	addTypedFinding(t, d, store, task.ID, "idor", "")
	addTypedFinding(t, d, store, task.ID, "ssrf", db.FindingQuarantined)
	addTypedFinding(t, d, store, task.ID, "rce", db.FindingFalsePositive)
	addTypedFinding(t, d, store, task.ID, "stored_xss", db.FindingDuplicate)
	addTypedFinding(t, d, store, task.ID, "file_upload", db.FindingIgnored)
	addTypedFinding(t, d, store, task.ID, "GraphQL 滥用", "")

	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(d.Assets(), d.Companies())
	overview := tools.graphOverviewData()
	raw, ok := overview["finding_type_counts"].(map[string]any)
	if !ok {
		t.Fatalf("finding_type_counts missing: %#v", overview["finding_type_counts"])
	}
	if cap, _ := raw["cap"].(int); cap != 3 {
		t.Fatalf("cap = %v, want 3 (standards hunting block)", raw["cap"])
	}
	rows, ok := raw["counts"].([]map[string]any)
	if !ok {
		t.Fatalf("counts rows missing: %#v", raw["counts"])
	}
	got := map[string]int{}
	for _, r := range rows {
		ty, _ := r["type"].(string)
		cnt, _ := r["count"].(int)
		got[ty] = cnt
	}
	want := map[string]int{"注入类": 2, "越权": 1, "graphql滥用": 1}
	if len(got) != len(want) {
		t.Fatalf("buckets = %#v, want %#v", got, want)
	}
	for ty, cnt := range want {
		if got[ty] != cnt {
			t.Fatalf("bucket %q = %d, want %d (all buckets: %#v)", ty, got[ty], cnt, got)
		}
	}
	// Excluded statuses must leave no bucket behind.
	for _, banned := range []string{"SSRF", "命令执行与反序列化", "存储型 XSS", "文件上传 getshell"} {
		if _, hit := got[banned]; hit {
			t.Fatalf("excluded status leaked into bucket %q: %#v", banned, got)
		}
	}
}

// TestGraphOverviewFindingTypeCountsIgnoresCrossTaskStatus pins the taskID
// scoping of the status cross-check: a finding node from the same exploration
// graph whose findings row belongs to another task must not be silently dropped
// (meta is queried per task).
func TestGraphOverviewFindingTypeCountsTaskScoped(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("scoped", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	// A finding node with a findings row under a foreign task id (node created
	// directly, row attached elsewhere) still counts for this task's graph.
	nodeID, err := store.AddNode(db.KindFinding, map[string]any{
		"summary": "foreign row", "vulnclass": "rce", "severity": "high",
	}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateTask("other", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(other.ID)
	if _, err := d.AddFinding(other.ID, nodeID, "rce", "n", "high", "foreign row", "e", "worker", nil); err != nil {
		t.Fatal(err)
	}

	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(d.Assets(), d.Companies())
	overview := tools.graphOverviewData()
	raw, ok := overview["finding_type_counts"].(map[string]any)
	if !ok {
		t.Fatalf("finding_type_counts missing: %#v", overview["finding_type_counts"])
	}
	rows, _ := raw["counts"].([]map[string]any)
	found := false
	for _, r := range rows {
		if r["type"] == "命令执行与反序列化" {
			found = true
		}
	}
	if !found {
		t.Fatalf("foreign-task status must not drop this task's node: %#v", raw["counts"])
	}
}

// TestRenderWorkerGraphOverviewDropsFindingTypeCounts mirrors the coverage
// deletion pattern: the worker's launch message reuses the planner's overview
// data, but direction-rebalancing signals are planner-only, so both the type
// distribution and the coverage block must be stripped from the worker view.
func TestRenderWorkerGraphOverviewDropsFindingTypeCounts(t *testing.T) {
	data := map[string]any{
		"findings_total": 3,
		"coverage":       map[string]any{"host_count": 2},
		"finding_type_counts": map[string]any{
			"cap":    3,
			"counts": []map[string]any{{"type": "注入类", "count": 3, "full": true}},
		},
	}
	rendered := renderWorkerGraphOverview(data)
	if !strings.Contains(rendered, "全局探索态势") {
		t.Fatalf("worker overview preamble missing: %q", rendered)
	}
	body := rendered[strings.Index(rendered, "{"):]
	var back map[string]any
	if err := json.Unmarshal([]byte(body), &back); err != nil {
		t.Fatalf("worker overview is not the marshalled data: %v; %q", err, rendered)
	}
	for _, key := range []string{"finding_type_counts", "coverage"} {
		if _, hit := back[key]; hit {
			t.Fatalf("worker view must drop planner-only key %q: %q", key, rendered)
		}
	}
	if back["findings_total"] != float64(3) {
		t.Fatalf("unrelated keys must survive: %#v", back)
	}
}
