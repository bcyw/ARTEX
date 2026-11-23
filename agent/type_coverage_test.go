package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// newTypeCoverageFixture returns a fresh task exploration plus a planner ToolSet
// wired the way the planner uses it (task id + asset store for the findings-row
// status cross-check). Catalog type names are never hardcoded here: every
// fixture value comes from srcCatalog() so this file stays free of type
// vocabulary (ADR-0004).
func newTypeCoverageFixture(t *testing.T) (*db.DB, *db.ExplorationStore, *ToolSet) {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("type coverage", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(d.Assets(), d.Companies())
	return d, store, tools
}

// typeCoverageFrom pulls the type_coverage rows out of an overview map.
func typeCoverageFrom(t *testing.T, overview map[string]any) []map[string]any {
	t.Helper()
	rows, ok := overview["type_coverage"].([]map[string]any)
	if !ok {
		t.Fatalf("type_coverage missing or wrong shape: %#v", overview["type_coverage"])
	}
	return rows
}

func typeCoverageRow(t *testing.T, rows []map[string]any, typ string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["type"] == typ {
			return r
		}
	}
	t.Fatalf("type_coverage has no row for %q: %#v", typ, rows)
	return nil
}

func rowInt(t *testing.T, row map[string]any, key string) int {
	t.Helper()
	v, ok := row[key].(int)
	if !ok {
		t.Fatalf("row %q field %q = %#v, want int", row["type"], key, row[key])
	}
	return v
}

// requireCatalogEntries fails when the hot-loaded catalog is too small for the
// fixture slices used below (the shipped default has 22 entries, 8 collectable).
func requireCatalogEntries(t *testing.T, n int) srcTypeCatalog {
	t.Helper()
	c := srcCatalog()
	if len(c.Entries) < n {
		t.Fatalf("catalog has %d entries, need at least %d", len(c.Entries), n)
	}
	if c.Cap <= 0 {
		t.Fatalf("catalog cap = %d, want positive", c.Cap)
	}
	return c
}

// TestGraphOverviewTypeCoverageCatalogOrder pins the shape of the row table: one
// row per catalog entry in catalog written order (collectable types first,
// explicitly-not-collected types included after), with the collect flag carried
// through — and an empty exploration graph degrades to all-zero counters instead
// of panicking.
func TestGraphOverviewTypeCoverageCatalogOrder(t *testing.T) {
	catalog := requireCatalogEntries(t, 1)
	_, _, tools := newTypeCoverageFixture(t)
	rows := typeCoverageFrom(t, tools.graphOverviewData())

	if len(rows) != len(catalog.Entries) {
		t.Fatalf("type_coverage rows = %d, want one per catalog entry (%d)", len(rows), len(catalog.Entries))
	}
	sawCollect, sawNoCollect := false, false
	for i, want := range catalog.Entries {
		got := rows[i]
		if got["type"] != want.Name {
			t.Fatalf("row %d type = %#v, want catalog entry %q (order must be catalog written order)", i, got["type"], want.Name)
		}
		if got["collect"] != want.Collect {
			t.Fatalf("row %d (%q) collect = %#v, want %v", i, want.Name, got["collect"], want.Collect)
		}
		// 空图：findings/intents 全 0，full 只由 cap 决定。
		if n := rowInt(t, got, "findings"); n != 0 {
			t.Fatalf("empty graph: row %q findings = %d, want 0", want.Name, n)
		}
		for _, key := range []string{"intents_open", "intents_running", "intents_done"} {
			if n := rowInt(t, got, key); n != 0 {
				t.Fatalf("empty graph: row %q %s = %d, want 0", want.Name, key, n)
			}
		}
		if full, _ := got["full"].(bool); full != (0 >= catalog.Cap) {
			t.Fatalf("empty graph: row %q full = %v, want %v", want.Name, full, 0 >= catalog.Cap)
		}
		if want.Collect {
			sawCollect = true
		} else {
			sawNoCollect = true
		}
	}
	// 票面要求目录全部条目都在表里，包括 collect:false 的「不挖」类型。
	if !sawCollect || !sawNoCollect {
		t.Fatalf("catalog should contain both collectable and non-collectable entries (collect=%v, no-collect=%v)", sawCollect, sawNoCollect)
	}
}

// TestGraphOverviewTypeCoverageUnavailableNodes degrades unreadable prefetches
// to zero counts while retaining the catalog rows.
func TestGraphOverviewTypeCoverageUnavailableNodes(t *testing.T) {
	catalog := requireCatalogEntries(t, 1)
	d, _, tools := newTypeCoverageFixture(t)
	d.Close()
	rows := typeCoverageFrom(t, tools.graphOverviewData())
	if len(rows) != len(catalog.Entries) {
		t.Fatalf("rows = %d, want %d despite unavailable nodes", len(rows), len(catalog.Entries))
	}
	for _, row := range rows {
		for _, key := range []string{"findings", "intents_open", "intents_running", "intents_done"} {
			if got := rowInt(t, row, key); got != 0 {
				t.Errorf("%s = %d, want 0 with unavailable nodes", key, got)
			}
		}
	}
}

// TestGraphOverviewTypeCoverageFindings pins the findings column: it folds alias
// spellings into the catalog bucket, excludes quarantined/false_positive/
// duplicate/ignored rows, agrees with finding_type_counts, and keeps catalog-outside
// buckets out of the coverage table (distribution, which is planner-wide, still
// carries them).
func TestGraphOverviewTypeCoverageFindings(t *testing.T) {
	catalog := requireCatalogEntries(t, 6)
	d, store, tools := newTypeCoverageFixture(t)

	taskID := tools.taskID
	first := catalog.Entries[0]
	addTypedFinding(t, d, store, taskID, first.Name, "")
	if len(first.Aliases) > 0 {
		addTypedFinding(t, d, store, taskID, first.Aliases[0], db.FindingConfirmed)
	}
	excluded := []string{db.FindingQuarantined, db.FindingFalsePositive, db.FindingDuplicate, db.FindingIgnored}
	for i, status := range excluded {
		addTypedFinding(t, d, store, taskID, catalog.Entries[i+1].Name, status)
	}
	// 目录外写法：分布里自成桶，覆盖表里不出现。
	const outside = "zzz-unknown-fixture-direction"
	addTypedFinding(t, d, store, taskID, outside, "")

	overview := tools.graphOverviewData()
	rows := typeCoverageFrom(t, overview)

	wantFirst := 1
	if len(first.Aliases) > 0 {
		wantFirst = 2
	}
	if n := rowInt(t, rows[0], "findings"); n != wantFirst {
		t.Fatalf("row %q findings = %d, want %d (canonical + alias fold)", first.Name, n, wantFirst)
	}
	for i := range excluded {
		name := catalog.Entries[i+1].Name
		if n := rowInt(t, typeCoverageRow(t, rows, name), "findings"); n != 0 {
			t.Fatalf("row %q findings = %d, want 0 (status %q is excluded)", name, n, excluded[i])
		}
	}
	if _, hit := typeCoverageRowNoFatal(rows, outside); hit {
		t.Fatalf("catalog-outside bucket %q must not appear in type_coverage", outside)
	}

	// 与 finding_type_counts 逐桶对齐：同一次概览里两个数字不得漂移。
	dist, ok := overview["finding_type_counts"].(map[string]any)
	if !ok {
		t.Fatalf("finding_type_counts missing: %#v", overview["finding_type_counts"])
	}
	distRows, _ := dist["counts"].([]map[string]any)
	counts := map[string]int{}
	for _, r := range distRows {
		ty, _ := r["type"].(string)
		counts[ty], _ = r["count"].(int)
	}
	for _, r := range rows {
		ty, _ := r["type"].(string)
		if n := rowInt(t, r, "findings"); n != counts[ty] {
			t.Fatalf("type_coverage[%q].findings = %d != finding_type_counts %d", ty, n, counts[ty])
		}
	}
	if _, hit := counts[srcFoldKey(outside)]; !hit {
		t.Fatalf("finding_type_counts should still carry the catalog-outside bucket %q: %#v", srcFoldKey(outside), counts)
	}
}

// TestGraphOverviewTypeCoverageUsesNodeStatusWithoutFindingRow verifies the
// fallback for historical graph-only findings through both planner counters.
func TestGraphOverviewTypeCoverageUsesNodeStatusWithoutFindingRow(t *testing.T) {
	catalog := requireCatalogEntries(t, 1)
	_, store, tools := newTypeCoverageFixture(t)
	typ := catalog.Entries[0].Name
	for _, state := range []string{"confirmed", "dismissed"} {
		if _, err := store.AddNode(db.KindFinding, map[string]any{"vulnclass": typ}, 0, state, "worker", nil); err != nil {
			t.Fatal(err)
		}
	}
	overview := tools.graphOverviewData()
	row := typeCoverageRow(t, typeCoverageFrom(t, overview), typ)
	if got := rowInt(t, row, "findings"); got != 1 {
		t.Errorf("graph-only findings = %d, want 1 (confirmed; dismissed excluded)", got)
	}
	dist := overview["finding_type_counts"].(map[string]any)["counts"].([]map[string]any)
	if len(dist) != 1 || dist[0]["count"] != 1 {
		t.Errorf("finding_type_counts = %#v, want one bucket with count 1", dist)
	}
}

func typeCoverageRowNoFatal(rows []map[string]any, typ string) (map[string]any, bool) {
	for _, r := range rows {
		if r["type"] == typ {
			return r, true
		}
	}
	return nil, false
}

// TestGraphOverviewTypeCoverageFull pins full = findings >= catalog.Cap: a bucket
// filled to the cap is full, a bucket below it is not.
func TestGraphOverviewTypeCoverageFull(t *testing.T) {
	catalog := requireCatalogEntries(t, 6)
	d, store, tools := newTypeCoverageFixture(t)

	// 找一个可收（受上限约束）的桶来填满；目录序可收类型在前。
	fullIdx := -1
	for i, e := range catalog.Entries {
		if e.Collect {
			fullIdx = i
			break
		}
	}
	if fullIdx < 0 {
		t.Fatal("catalog has no collectable entry")
	}
	fullName := catalog.Entries[fullIdx].Name
	belowName := catalog.Entries[(fullIdx+1)%len(catalog.Entries)].Name
	if belowName == fullName {
		t.Fatal("need two distinct catalog entries")
	}
	for i := 0; i < catalog.Cap; i++ {
		addTypedFinding(t, d, store, tools.taskID, fullName, db.FindingConfirmed)
	}
	addTypedFinding(t, d, store, tools.taskID, belowName, db.FindingConfirmed)

	rows := typeCoverageFrom(t, tools.graphOverviewData())
	fullRow := typeCoverageRow(t, rows, fullName)
	if n := rowInt(t, fullRow, "findings"); n != catalog.Cap {
		t.Fatalf("row %q findings = %d, want cap %d", fullName, n, catalog.Cap)
	}
	if full, _ := fullRow["full"].(bool); !full {
		t.Fatalf("row %q (findings=%d, cap=%d) full = false, want true", fullName, catalog.Cap, catalog.Cap)
	}
	belowRow := typeCoverageRow(t, rows, belowName)
	if n := rowInt(t, belowRow, "findings"); n != 1 {
		t.Fatalf("row %q findings = %d, want 1", belowName, n)
	}
	if full, _ := belowRow["full"].(bool); full {
		t.Fatalf("row %q (findings=1, cap=%d) full = true, want false", belowName, catalog.Cap)
	}
}

// TestGraphOverviewTypeCoverageIntentStates pins the intents_* columns: intents
// carrying vuln_type are folded to the catalog bucket and grouped open/running/
// terminal(done); paused, untyped and catalog-outside intents are not counted.
func TestGraphOverviewTypeCoverageIntentStates(t *testing.T) {
	catalog := requireCatalogEntries(t, 2)
	_, store, tools := newTypeCoverageFixture(t)
	typ := catalog.Entries[0].Name
	alias := typ
	if len(catalog.Entries[0].Aliases) > 0 {
		alias = catalog.Entries[0].Aliases[0]
	}
	const outside = "zzz-unknown-fixture-direction"

	add := func(vulnType, state string) {
		t.Helper()
		payload := map[string]any{"summary": "fixture " + state}
		if vulnType != "" {
			payload["vuln_type"] = vulnType
		}
		if _, err := store.AddNode(db.KindIntent, payload, 5, state, "planner", nil); err != nil {
			t.Fatalf("add intent (%s, %s): %v", vulnType, state, err)
		}
	}
	add(typ, "open")
	add(alias, "open") // 别名折叠进同一桶
	add(typ, "running")
	add(typ, "done")
	add(typ, "blocked") // 终态一律计 done
	add(typ, "exhausted")
	add(typ, "stopped")
	add(typ, "paused")  // 暂停不计
	add(typ, "deleted") // 已删除不计
	add("", "open")     // 无 vuln_type 不计
	add(outside, "open")

	rows := typeCoverageFrom(t, tools.graphOverviewData())
	row := typeCoverageRow(t, rows, typ)
	if n := rowInt(t, row, "intents_open"); n != 2 {
		t.Fatalf("intents_open = %d, want 2 (canonical + alias, paused/untyped excluded)", n)
	}
	if n := rowInt(t, row, "intents_running"); n != 1 {
		t.Fatalf("intents_running = %d, want 1", n)
	}
	if n := rowInt(t, row, "intents_done"); n != 4 {
		t.Fatalf("intents_done = %d, want 4 (done + blocked + exhausted + stopped)", n)
	}
	if _, hit := typeCoverageRowNoFatal(rows, outside); hit {
		t.Fatalf("catalog-outside intent must not create a type_coverage row")
	}
}

// TestGraphOverviewTypeCoverageIncludesOlderIntents verifies that the coverage
// counters describe the whole task even when its intent detail windows overflow.
func TestGraphOverviewTypeCoverageIncludesOlderIntents(t *testing.T) {
	catalog := requireCatalogEntries(t, 1)
	_, store, tools := newTypeCoverageFixture(t)
	typ := catalog.Entries[0].Name
	for _, state := range []string{"open", "running", "done", "blocked", "exhausted", "stopped"} {
		if _, err := store.AddNode(db.KindIntent, map[string]any{"vuln_type": typ}, 5, state, "planner", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Newer reconnaissance intents push every typed intent beyond the old
	// 300-node prefetch window without contributing to the type counters.
	for range 301 {
		if _, err := store.AddNode(db.KindIntent, map[string]any{"summary": "recon"}, 0, "done", "planner", nil); err != nil {
			t.Fatal(err)
		}
	}
	row := typeCoverageRow(t, typeCoverageFrom(t, tools.graphOverviewData()), typ)
	for key, want := range map[string]int{"intents_open": 1, "intents_running": 1, "intents_done": 4} {
		if got := rowInt(t, row, key); got != want {
			t.Errorf("%s = %d, want %d including older intents", key, got, want)
		}
	}
}

// TestRenderWorkerGraphOverviewDropsTypeCoverage: the coverage table is a
// planner scheduling signal (which catalog directions are still blank), so the
// worker's launch view must strip it exactly like finding_type_counts/coverage.
func TestRenderWorkerGraphOverviewDropsTypeCoverage(t *testing.T) {
	data := map[string]any{
		"findings_total": 2,
		"type_coverage":  []map[string]any{{"type": "x", "collect": true}},
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
	if _, hit := back["type_coverage"]; hit {
		t.Fatalf("worker view must drop type_coverage: %q", rendered)
	}
	if back["findings_total"] != float64(2) {
		t.Fatalf("unrelated keys must survive: %#v", back)
	}
}
