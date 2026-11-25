package db

import (
	"context"
	"path/filepath"
	"testing"
)

// Uncertainty is retained across repeated retests and a database reopen; it
// cannot replace the original disposition or erase the reasons for each run.
func TestRetestConsecutiveInconclusive(t *testing.T) {
	for _, status := range []string{FindingPending, FindingInProgress, FindingConfirmed, FindingResolved, FindingFixed, FindingFalsePositive, FindingIgnored, FindingDuplicate, FindingRiskAccepted, FindingQuarantined} {
		t.Run(status, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "retest.sqlite")
			d, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.Close() })
			fid, err := d.AddFinding(0, 0, "retest-consecutive", "测试发现", "high", "summary", "original proof", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.SetFindingStatus(fid, status); err != nil {
				t.Fatal(err)
			}
			reasons := map[int64]string{}
			for _, reason := range []string{"会话已过期，无法重放原身份", "环境权限变化，正常对照不可用", "工具失败，尚未得到响应"} {
				r := runRetestForFinding(t, d, t.Context(), fid, "inconclusive", reason)
				reasons[r.ID] = reason
				if got := findingStatusByID(t, d, fid); got != status {
					t.Fatalf("inconclusive changed disposition: got %s, want %s", got, status)
				}
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			finding, err := d.GetFinding(fid)
			if err != nil || finding == nil || finding.Status != status || finding.Evidence != "original proof" {
				t.Fatalf("reopened finding changed: %+v, %v", finding, err)
			}
			history, err := d.ListFindingRetests(fid)
			if err != nil || len(history) != len(reasons) {
				t.Fatalf("reopened retest history: %+v, %v", history, err)
			}
			for _, r := range history {
				if r.Status != "completed" || r.Verdict != "inconclusive" || r.Summary != reasons[r.ID] || r.Evidence != "evidence markdown" || r.FinishedAt == nil {
					t.Fatalf("uncertainty/reason/evidence lost: %+v", r)
				}
			}
		})
	}
}

// runRetestForFinding 走真实复测流程：建复测(含会话) → 启动 → 记录结论 → 完成。
func runRetestForFinding(t *testing.T, d *DB, ctx context.Context, findingID int64, verdict, summary string) *FindingRetest {
	t.Helper()
	r, _, created, err := d.CreateFindingRetest(ctx, findingID, "")
	if err != nil || r == nil {
		t.Fatalf("CreateFindingRetest: %v %v", r, err)
	}
	if !created {
		t.Fatalf("复测被去重(不应有并发活动复测): finding=%d", findingID)
	}
	if _, err := d.StartFindingRetest(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.RecordFindingRetestResult(ctx, *r.ConversationID, verdict, summary, "evidence markdown"); err != nil {
		t.Fatalf("RecordFindingRetestResult(%s): %v", verdict, err)
	}
	if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
		t.Fatalf("FinishFindingRetest(%s): %v", verdict, err)
	}
	return r
}

func findingStatusByID(t *testing.T, d *DB, id int64) string {
	t.Helper()
	f, err := d.GetFinding(id)
	if err != nil || f == nil {
		t.Fatalf("GetFinding(%d): %v %v", id, f, err)
	}
	return f.Status
}
