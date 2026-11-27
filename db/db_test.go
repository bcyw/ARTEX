package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// testDSN returns the configured DSN, skipping the test when neither the env var
// nor a config file supplies one (DSN no longer has a built-in default).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Fatalf("no database config (%v)", err)
	}
	return dsn
}

// TestOpenSeed opens the live dev PG, applies schema, seeds, and verifies the
// builtin agents + their variable catalog exist. Skips if PG is unreachable.
func TestOpenSeed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	defer d.Close()

	wantAgents := len(builtinAgents)
	var agents int
	if err := d.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("want %d builtin agents, got %d", wantAgents, agents)
	}

	// planner should have at least its seeded catalog vars
	wantPlannerVars := 0
	for _, a := range builtinAgents {
		if a.key == "planner" {
			wantPlannerVars = len(a.vars)
			break
		}
	}
	var plannerVars int
	if err := d.QueryRow(`
SELECT count(*) FROM agent_prompt_vars v
JOIN agents a ON a.id = v.agent_id
WHERE a.key = 'planner'`).Scan(&plannerVars); err != nil {
		t.Fatal(err)
	}
	if plannerVars < wantPlannerVars {
		t.Fatalf("want at least %d planner vars, got %d", wantPlannerVars, plannerVars)
	}

	// re-open must be idempotent (no duplicate agents)
	d2, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if err := d2.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("after re-open want %d agents, got %d", wantAgents, agents)
	}
}

func TestOpenSchema2PreservesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema2.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := d.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("expected a new database to use schema 2, got %d", version)
	}

	task, err := d.CreateTask("schema2 fixture", "preserve schema2 state", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var serviceID, endpointID int64
	if err := d.QueryRow(`
INSERT INTO assets(type,url,service_type,domain,port)
VALUES ('service','https://schema2.example','http','schema2.example',443)
RETURNING id`).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`
INSERT INTO assets(type,url,method,service_id)
VALUES ('endpoint','https://schema2.example/users/{id}','GET',$1)
RETURNING id`, serviceID).Scan(&endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`
INSERT INTO endpoint_candidates(task_id,service_url,path_template,method,observations)
VALUES ($1,'https://schema2.example','/pending','GET','[{"source":"test"}]')`, task.ID); err != nil {
		t.Fatal(err)
	}
	const snapshot = `{"marker":"keep-schema2"}`
	if _, err := d.Exec(`
INSERT INTO endpoint_migration_audit(legacy_asset_id,canonical_asset_id,outcome,snapshot)
VALUES (900001,$1,'merged',$2)`, endpointID, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d, err = Open(path)
	if err != nil {
		t.Fatalf("open existing schema2 database: %v", err)
	}
	defer d.Close()
	if err := d.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 2 {
		t.Fatalf("schema version must remain 2, got %d: %v", version, err)
	}
	var gotServiceID int64
	if err := d.QueryRow(`SELECT service_id FROM assets WHERE id=$1`, endpointID).Scan(&gotServiceID); err != nil || gotServiceID != serviceID {
		t.Fatalf("endpoint service relationship changed: got %d, want %d: %v", gotServiceID, serviceID, err)
	}
	var candidateCount, auditCount int
	var gotSnapshot string
	if err := d.QueryRow(`SELECT count(*) FROM endpoint_candidates WHERE task_id=$1 AND observations='[{"source":"test"}]'`, task.ID).Scan(&candidateCount); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT count(*),max(snapshot) FROM endpoint_migration_audit WHERE legacy_asset_id=900001`).Scan(&auditCount, &gotSnapshot); err != nil {
		t.Fatal(err)
	}
	if candidateCount != 1 || auditCount != 1 || gotSnapshot != snapshot {
		t.Fatalf("schema2 records changed after reopen: candidates=%d audits=%d snapshot=%q", candidateCount, auditCount, gotSnapshot)
	}
}

func TestOpenRejectsUnknownSchemaVersionWithoutChangingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema3.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("schema3-sentinel", "preserve-me"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`PRAGMA user_version=3`); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected an unsupported future schema version to be rejected")
	}

	conn, err := sql.Open("artex-sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var version int
	if err := conn.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("unsupported version must remain unchanged, got %d: %v", version, err)
	}
	var value string
	if err := conn.QueryRow(`SELECT value FROM settings WHERE key='schema3-sentinel'`).Scan(&value); err != nil || value != "preserve-me" {
		t.Fatalf("database data changed while rejecting unsupported version: %q: %v", value, err)
	}
}
