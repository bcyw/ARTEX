package db

import (
	"context"
	"testing"
)

// TestRecordFindingQuarantine 验证 SRC 黑名单硬闸的入库行为：
// Quarantine=true → findings.status='quarantined'；默认路径仍为 pending。
func TestRecordFindingQuarantine(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("quarantine-test", "测试目标")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	in := RecordFindingInput{
		ExplorationID: expID,
		VulnClass:    "clickjacking", Severity: "low",
		Summary: "点击劫持", Evidence: "poc", Worker: "worker",
		Quarantine: true,
	}
	out, err := es.RecordFinding(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, out.FindingID)

	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil {
		t.Fatalf("GetFinding: %v %v", f, err)
	}
	if f.Status != FindingQuarantined {
		t.Fatalf("quarantine 入库状态 = %q, want %q", f.Status, FindingQuarantined)
	}

	// 默认路径不受影响。
	normal := in
	normal.VulnClass, normal.Quarantine = "sqli", false
	out2, err := es.RecordFinding(context.Background(), normal)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, out2.FindingID)

	f2, err := d.GetFinding(out2.FindingID)
	if err != nil || f2 == nil {
		t.Fatal(err)
	}
	if f2.Status != FindingPending {
		t.Fatalf("默认入库状态 = %q, want %q", f2.Status, FindingPending)
	}

	// quarantined 是合法 triage 状态(人工可在详情页放行)。
	if !ValidFindingStatus(FindingQuarantined) {
		t.Fatal("quarantined 应在 ValidFindingStatus 白名单内")
	}
}
