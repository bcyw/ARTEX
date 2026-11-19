package db

import (
	"database/sql"
	"testing"
)

func TestListTaskReportFindingsOnlyConfirmedAndOrdered(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("报告查询测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	es := d.Exploration(task.ExplorationID)
	ctx := t.Context()

	low, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: "信息泄露", Name: "低危漏洞",
		Severity: "low", Summary: "工作摘要", Evidence: "poc",
		Description: "交付描述", Impact: "影响", Remediation: "修复", Session: "测试账号 A",
	})
	if err != nil {
		t.Fatal(err)
	}
	critical, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: "SQL注入", Name: "高危漏洞",
		Severity: "critical", Summary: "工作摘要", Description: "临界描述",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, VulnClass: "XSS", Severity: "high", Summary: "未确认",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{low.FindingID, critical.FindingID} {
		if _, err := d.SetFindingStatus(id, FindingConfirmed); err != nil {
			t.Fatal(err)
		}
	}

	mkSnapshot := func(trafficID, target, head string) TrafficEvidenceSnapshot {
		s := TrafficEvidenceSnapshot{
			SourceTrafficID: trafficID, CapturedAt: 1, URL: target, Method: "GET", Status: 200,
			ReqHead: head, RespHead: "HTTP 200", ReqHash: trafficID + "-req", RespHash: trafficID + "-resp",
			ReqLen: 1, RespLen: 1,
		}
		s.ID = TrafficSnapshotID(s)
		return s
	}
	err = d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		return AddFindingTrafficTx(tx, critical.FindingID, []PreparedTrafficEvidence{
			{Ref: TrafficRef{TrafficID: "t-proof", Role: "proof", Note: "证明"}, Snapshot: mkSnapshot("t-proof", "https://a/2", "GET /2 HTTP/1.1\nHost: a")},
			{Ref: TrafficRef{TrafficID: "t-base", Role: "baseline", Note: "对照"}, Snapshot: mkSnapshot("t-base", "https://a/1", "GET /1 HTTP/1.1\nHost: a")},
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := d.ListTaskReportFindings(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("only confirmed findings belong in the report: want 2, got %d", len(out))
	}
	if out[0].ID != critical.FindingID || out[1].ID != low.FindingID {
		t.Fatalf("want critical first then low, got %d,%d", out[0].ID, out[1].ID)
	}
	if out[1].ID == pending.FindingID {
		t.Fatal("pending finding leaked into the report")
	}
	if got := out[1].Sections; got.Description != "交付描述" || got.Impact != "影响" || got.Remediation != "修复" || got.Session != "测试账号 A" {
		t.Fatalf("report sections not loaded: %+v", got)
	}
	if len(out[0].TrafficBindings) != 2 {
		t.Fatalf("bindings not attached: %+v", out[0].TrafficBindings)
	}
	if out[0].TrafficBindings[0].Role != "proof" || out[0].TrafficBindings[1].Role != "baseline" {
		t.Fatalf("bindings must keep position order: %+v", out[0].TrafficBindings)
	}

	empty, err := d.ListTaskReportFindings(ctx, 0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("no task means no report: want (0,nil), got (%d,%v)", len(empty), err)
	}
}
