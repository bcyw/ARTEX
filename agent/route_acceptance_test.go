package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// 票 05：高价值挖掘整体验收。两条端到端编排断言，其余清单项由
// route_orchestration / route_continuation / route_admission / intent_type /
// finding_type_anchor / oob_* 与 server/mining_standards 测试覆盖：
// - 无类型路线侦察 → 证据充分后才允许可收类型正式验证；
//   类型缺失、collect: no 或目录外未知类型仍拒绝正式验证。
// - OOB 回调只是中间证据：不自动产生 finding、RCE 结论或严重度。
// 默认不连公共 Interactsh 或真实目标（fakeSession 替身）。

// acceptanceCatalog 写一份可编辑验收目录：测试甲类可收、测试拒收类 collect: no。
func acceptanceCatalog(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src-acceptance.md")
	if err := os.WriteFile(path, []byte("~~~types\ntype: 测试甲类\ncollect: yes\naliases: alpha_test\nproof: 甲类最小证明物\ntype: 测试拒收类\ncollect: no\naliases: blocked_test\nproof: 拒收类证明物\nstop: 只有观察没有真实影响\n~~~\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	t.Cleanup(func() { SrcAcceptancePath("") })
}

func TestAcceptanceRouteReconToTypedVerificationGate(t *testing.T) {
	acceptanceCatalog(t)
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("acceptance typed gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	tools := NewToolSet(ts, "planner")
	tools.SetTaskID(task.ID)

	route := map[string]any{"entry": "https://example.test/import", "family": "deserialization", "component": "custom-parser"}

	// ① 未知组件允许无类型路线侦察意图（无 CVE/预设枚举要求）。
	out, failed := callIntent(t, tools, map[string]any{"summary": "侦察自定义导入入口", "route": route})
	if failed {
		t.Fatalf("无类型路线侦察应被允许: %s", out)
	}
	reconID := parseCreatedIntentID(t, out)

	// ② OOB 回调事实落地后，带可收类型的正式验证意图允许建立。
	fact, err := ts.AddNode(db.KindFact, map[string]any{
		"summary": "DNS 回调已确认", "confidence": "observed",
		"evidence": "dns probe-1 from 198.51.100.9",
		"outcome":  "progress",
		"route":    route,
	}, 8, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Link(reconID, db.RelYields, fact); err != nil {
		t.Fatal(err)
	}
	route2 := map[string]any{"entry": route["entry"], "family": route["family"], "component": route["component"], "tested": []string{"dns-gadget"}}
	out, failed = callIntent(t, tools, map[string]any{
		"summary": "正式验证反序列化 RCE 危害", "vuln_type": "测试甲类", "proof": "甲类最小证明物",
		"parent_ids": []int64{fact}, "route": route2,
	})
	if failed {
		t.Fatalf("证据充分后的可收类型正式验证应被允许: %s", out)
	}
	// 意图确实建立，且 vuln_type/proof 按目录校验结果落库（而非仅"未报错"）。
	typedID := parseCreatedIntentID(t, out)
	typedPayload := routeIntentPayload(t, ts, typedID)
	if typedPayload["vuln_type"] != "测试甲类" || typedPayload["proof"] != "甲类最小证明物" {
		t.Fatalf("可收类型正式验证意图应带目录类型与证明物落库: %v", typedPayload)
	}

	// ③ 目录校验不被路线绕开：collect: no、未知类型仍拒绝。
	out, failed = callIntent(t, tools, map[string]any{"summary": "验证拒收类", "vuln_type": "测试拒收类", "route": route2})
	if !failed {
		t.Fatalf("collect: no 类型不得因路线存在而放行: %s", out)
	}
	if !strings.Contains(out, "测试拒收类") || !strings.Contains(out, "真实影响") {
		t.Fatalf("拒收文案应引用目录条目及其 stop 规则: %s", out)
	}
	out, failed = callIntent(t, tools, map[string]any{"summary": "验证未知类型", "vuln_type": "完全未知名型", "route": route2})
	if !failed {
		t.Fatalf("目录外未知类型不得进入正式验证: %s", out)
	}
}

func TestAcceptanceOOBCallbackDoesNotAutoFind(t *testing.T) {
	acceptanceCatalog(t)
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("acceptance no autofind", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	worker := NewToolSet(ts, "worker-1")
	worker.SetTaskID(task.ID)
	worker.SetAssetStore(d.Assets(), d.Companies())
	intentID, err := ts.AddIntent(map[string]any{"summary": "验证反序列化入口", "route": map[string]any{"entry": "https://example.test/import", "family": "deserialization"}}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)

	// 匹配回调：只落 progress 事实。
	fs := &fakeSession{url: "nonce.example.test"}
	fs.interactions = []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1", FullID: "probe-1.nonce.example.test", Remote: "198.51.100.9"}}
	res, err := worker.oobPoll(fs).Call(t.Context(), json.RawMessage(`{"wait":1}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("oob_poll 失败: %v %s", err, res.Flatten())
	}
	factID := int64(decode(t, res.Flatten())["fact_id"].(float64))
	fact, err := ts.GetNode(factID)
	if err != nil || fact == nil || fact.Kind != db.KindFact {
		t.Fatalf("回调应是事实而非 finding: %v %+v", err, fact)
	}
	var p map[string]any
	if err := json.Unmarshal(fact.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p["outcome"] != "progress" {
		t.Fatalf("回调事实 outcome 应为 progress，不得宣称 RCE/危害: %v", p)
	}
	for _, key := range []string{"severity", "rce", "exploit_success"} {
		if _, ok := p[key]; ok {
			t.Fatalf("回调事实不得携带 %q: %v", key, p)
		}
	}

	// 本任务下不得出现任何 finding 行——完整漏洞仍需危害与复现证据。
	findings, _, err := d.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprintf("%d", task.ID)}, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("OOB 回调不得自动生成 finding，got %d 行", len(findings))
	}
}
