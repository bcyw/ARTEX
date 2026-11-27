package db

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed testdata/endpoint_v1.sql
var endpointV1Schema string

func TestMigrationFailureRollsBackSchemaAndData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "migration-failure.sqlite")
	conn, err := sql.Open("artex-sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(endpointV1Schema + schemaSQL); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.Exec(`
INSERT INTO assets(id,type,url,method) VALUES(501,'endpoint','https://rollback.example/items/1','GET');
INSERT INTO endpoint_migration_audit(legacy_asset_id,canonical_asset_id,outcome,snapshot)
VALUES(501,501,'preexisting','{"marker":"keep"}')`); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("expected the preexisting audit conflict to abort migration")
	}

	check, err := sql.Open("artex-sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version, serviceColumns, audits int
	if err := check.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT count(*) FROM pragma_table_info('assets') WHERE name='service_id'`).Scan(&serviceColumns); err != nil {
		t.Fatal(err)
	}
	var url string
	if err := check.QueryRow(`SELECT url FROM assets WHERE id=501`).Scan(&url); err != nil {
		t.Fatal(err)
	}
	var snapshot string
	if err := check.QueryRow(`SELECT count(*),max(snapshot) FROM endpoint_migration_audit WHERE legacy_asset_id=501`).Scan(&audits, &snapshot); err != nil {
		t.Fatal(err)
	}
	if version != 1 || serviceColumns != 0 || url != "https://rollback.example/items/1" || audits != 1 || snapshot != `{"marker":"keep"}` {
		t.Fatalf("failed migration was not atomic: version=%d service_columns=%d url=%q audits=%d snapshot=%q", version, serviceColumns, url, audits, snapshot)
	}
}

func TestMigrateEndpointCanonicalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	conn, err := sql.Open("artex-sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	legacy := &DB{conn}
	// The frozen assets table is created first. CREATE TABLE IF NOT EXISTS
	// supplies unrelated tables but cannot add service_id to this old table.
	if _, err = legacy.Exec(endpointV1Schema + schemaSQL); err != nil {
		t.Fatal(err)
	}
	firstTask, err := legacy.CreateTask("migration", "migration", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	secondTask, err := legacy.CreateTask("other", "other", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO assets(id,type,url,service_type,domain,port,service_name,page_title,technologies) VALUES(90,'service','https://migrate.example:443','http','migrate.example',443,'HTTPS','legacy service metadata','["legacy"]')`,
		`INSERT INTO assets(id,type,url,service_type,domain,port,service_name,page_title,technologies) VALUES(91,'service','https://migrate.example','http','migrate.example',443,'HTTPS','duplicate service metadata','["secondary"]')`,
		`INSERT INTO assets(id,type,url,method,task_ids,params,extra,last_seen) VALUES(100,'endpoint','https://Migrate.example:443/users/1?id=1','get',json_array($1),'[{"location":"header","name":"Cookie","value":"SECRET"},{"location":"query","name":"id","source":"static","evidence":[{"artifact_path":"old.js"}]}]','{"first":true}','2026-01-01 00:00:00+00:00')`,
		`INSERT INTO assets(id,type,url,method,task_ids,params,extra,last_seen) VALUES(101,'endpoint','https://migrate.example/users/2?id=2','GET',json_array($2),'[{"location":"query","name":"id","source":"traffic","evidence":[{"traffic_id":"old-flow"}]}]','{"second":true}','2026-02-01 00:00:00+00:00')`,
		`INSERT INTO assets(id,type,url,method) VALUES(102,'endpoint','https://migrate.example/users/3','POST')`,
		`INSERT INTO assets(id,type,url,method) VALUES(103,'endpoint','/relative-legacy','GET')`,
	} {
		if _, err := legacy.Exec(stmt, firstTask.ID, secondTask.ID); err != nil {
			t.Fatal(err)
		}
	}
	hint, _, err := legacy.Exploration(firstTask.ExplorationID).BrowserImport("old-flow", "https://migrate.example/users/2", 101, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Exploration(firstTask.ExplorationID).Anchor(hint, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`UPDATE exploration_nodes SET payload=json_set(payload,'$.asset_ids',json('[100,101]')) WHERE id=$1`, hint); err != nil {
		t.Fatal(err)
	}
	finding, err := legacy.AddFinding(firstTask.ID, hint, "fixture", "fixture", SeverityLow, "summary", "evidence", "worker", []int64{100, 101})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`UPDATE task_asset_links SET source='agent',source_summary='original provenance' WHERE asset_id=101`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		d, err := Open(path)
		if err != nil {
			t.Fatalf("open migrated store (run %d): %v", run, err)
		}
		assets, err := d.Assets().GetByIDs([]int64{100, 101, 102, 103})
		if err != nil || len(assets) != 3 {
			t.Fatalf("migration must merge duplicates and retain distinct/invalid rows: %v %v", assets, err)
		}
		byID := map[int64]*Asset{}
		for _, a := range assets {
			byID[a.ID] = a
		}
		a := byID[100]
		if a == nil || a.URL != "https://migrate.example/users/{id}" || a.Method != "GET" || a.ServiceID == nil || len(a.TaskIDs) != 2 || a.LastSeen != "2026-02-01 00:00:00+00:00" {
			t.Fatalf("wrong survivor: %+v", a)
		}
		if a.ServiceID == nil || *a.ServiceID != 90 {
			t.Fatalf("endpoint should retain existing default-port service: %+v", a.ServiceID)
		}
		var serviceURL, serviceTitle string
		if err := d.QueryRow(`SELECT url,page_title FROM assets WHERE id=90 AND type='service'`).Scan(&serviceURL, &serviceTitle); err != nil || serviceURL != "https://migrate.example" || serviceTitle != "legacy service metadata" {
			t.Fatalf("legacy HTTP service was not canonicalized/preserved: %q %q %v", serviceURL, serviceTitle, err)
		}
		var serviceCount, technologyCount int
		if err := d.QueryRow(`SELECT count(*),max(json_array_length(technologies)) FROM assets WHERE type='service' AND service_type='http' AND url='https://migrate.example'`).Scan(&serviceCount, &technologyCount); err != nil || serviceCount != 1 || technologyCount != 2 {
			t.Fatalf("legacy HTTP service duplicates were not merged: count=%d technologies=%d err=%v", serviceCount, technologyCount, err)
		}
		raw, _ := json.Marshal(a.Params)
		if strings.Contains(string(raw), "SECRET") || !strings.Contains(string(raw), "old.js") || !strings.Contains(string(raw), "old-flow") || !strings.Contains(string(raw), `"path"`) {
			t.Fatalf("migration lost provenance or retained credentials: %s", raw)
		}
		var anchors, provenance, audit, version int
		if err := d.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=100`, hint).Scan(&anchors); err != nil || anchors != 1 {
			t.Fatalf("anchor remap: %d %v", anchors, err)
		}
		var nodeRefs, findingRefs []byte
		if err := d.QueryRow(`SELECT json_extract(payload,'$.asset_ids') FROM exploration_nodes WHERE id=$1`, hint).Scan(&nodeRefs); err != nil || string(nodeRefs) != "[100]" {
			t.Fatalf("dangling JSON asset references in node: %s %v", nodeRefs, err)
		}
		if err := d.QueryRow(`SELECT asset_ids FROM findings WHERE id=$1`, finding).Scan(&findingRefs); err != nil || string(findingRefs) != "[100]" {
			t.Fatalf("dangling JSON asset references in finding: %s %v", findingRefs, err)
		}
		var nodeType, findingType string
		if err := d.QueryRow(`SELECT json_type(payload,'$.asset_ids') FROM exploration_nodes WHERE id=$1`, hint).Scan(&nodeType); err != nil || nodeType != "array" {
			t.Fatalf("node asset_ids must remain a JSON array: type=%q err=%v", nodeType, err)
		}
		if err := d.QueryRow(`SELECT json_type(asset_ids) FROM findings WHERE id=$1`, finding).Scan(&findingType); err != nil || findingType != "array" {
			t.Fatalf("finding asset_ids must remain a JSON array: type=%q err=%v", findingType, err)
		}
		if err := d.QueryRow(`SELECT count(*) FROM task_asset_links WHERE task_id=$1 AND asset_id=100 AND source_summary='original provenance'`, secondTask.ID).Scan(&provenance); err != nil || provenance != 1 {
			t.Fatalf("task source remap: %d %v", provenance, err)
		}
		if err := d.QueryRow(`SELECT count(*) FROM endpoint_migration_audit WHERE legacy_asset_id IN (100,101,102,103)`).Scan(&audit); err != nil || audit != 4 {
			t.Fatalf("migration must be auditable and idempotent: %d %v", audit, err)
		}
		if err := d.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
			t.Fatalf("schema version: %d %v", version, err)
		}
		if rows, err := d.Query(`PRAGMA foreign_key_check`); err != nil {
			t.Fatal(err)
		} else {
			if rows.Next() {
				t.Fatal("migration left a broken foreign key")
			}
			rows.Close()
		}
		d.Close()
	}
}
