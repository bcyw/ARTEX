package db

import (
	"context"
	"testing"
)

// TestRetestConsecutiveInconclusive 验证 SRC 复测纪律的「连续」语义：
// 连续 2 次 inconclusive → false_positive；中间一次 reproduced 断链重数，
// 之后单次 inconclusive 不触发误报判定。
func TestRetestConsecutiveInconclusive(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("retest-consecutive-test", "测试目标")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	out, err := es.RecordFinding(context.Background(), RecordFindingInput{
		ExplorationID: expID,
		VulnClass:     "sqli", Severity: "high",
		Summary: "注入", Evidence: "poc", Worker: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM findings WHERE id=$1`, out.FindingID)

	ctx := context.Background()

	// 第 1 次 inconclusive：不触发误报。
	_ = runRetestForFinding(t, d, ctx, out.FindingID, "inconclusive", "第一次无法确认")
	if s := findingStatusByID(t, d, out.FindingID); s != FindingPending {
		t.Fatalf("第 1 次 inconclusive 后状态 = %q, want pending", s)
	}

	// 中间一次 reproduced：断链 + 佐证有效。
	_ = runRetestForFinding(t, d, ctx, out.FindingID, "reproduced", "复现成功")

	// 之后单次 inconclusive：连续数只有 1，不触发误报。
	_ = runRetestForFinding(t, d, ctx, out.FindingID, "inconclusive", "再次无法确认")
	if s := findingStatusByID(t, d, out.FindingID); s != FindingPending {
		t.Fatalf("断链后单次 inconclusive 状态 = %q, want pending", s)
	}

	// 再来一次 inconclusive：连续数 2 → 误报。
	_ = runRetestForFinding(t, d, ctx, out.FindingID, "inconclusive", "第三次无法确认")
	if s := findingStatusByID(t, d, out.FindingID); s != FindingFalsePositive {
		t.Fatalf("连续 2 次 inconclusive 后状态 = %q, want false_positive", s)
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
