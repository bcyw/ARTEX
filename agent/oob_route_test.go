package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// 票据 01：route 可选字段接缝——add_intent / record_fact 接受结构化 route
// 对象（family/component/entry/hypothesis/next_step），原样落入节点 payload，
// 不改 SQLite schema；省略时行为与从前完全一致。

func routeToolSet(t *testing.T) *ToolSet {
	t.Helper()
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("route fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	return NewToolSet(ts, "w1")
}

func TestAddIntentRouteField(t *testing.T) {
	tsx := routeToolSet(t)
	tool := tsx.addIntent()
	raw := `{"summary":"测 Java 反序列化","route":{"family":"deserialization","component":"commons-collections 3.2","entry":"/api/import","hypothesis":"YSOSERP CMS 链可达","next_step":"投递 payload 并 oob_poll"}}`
	res, err := tool.Call(context.Background(), json.RawMessage(raw), nil)
	if err != nil {
		t.Fatalf("add_intent 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("带 route 的意图被拒: %s", res.Flatten())
	}
}

func TestAddIntentNoRouteUnchanged(t *testing.T) {
	tsx := routeToolSet(t)
	tool := tsx.addIntent()
	res, err := tool.Call(context.Background(), json.RawMessage(`{"summary":"纯侦察方向"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("省略 route 应照常工作: %v %s", err, res.Flatten())
	}
}

func TestRecordFactRouteField(t *testing.T) {
	tsx := routeToolSet(t)
	tool := tsx.recordFact()
	raw := `{"summary":"OOB 回调确认 SSRF","detail":"dns 回调来自目标出口","route":{"family":"ssrf","component":"","entry":"https://t/import","hypothesis":"url 参数可外联","next_step":"升级 http 回调拿内容"},"confidence":"observed"}`
	res, err := tool.Call(context.Background(), json.RawMessage(raw), nil)
	if err != nil {
		t.Fatalf("record_fact 失败: %v", err)
	}
	if res.IsError {
		t.Fatalf("带 route 的事实被拒: %s", res.Flatten())
	}
}

func TestRouteRejectedForBatchScope(t *testing.T) {
	// route 只描述单条路线：批量里的每条意图各自带 route，顶层 route 无意义，
	// 应明确拒绝而不是静默套用到所有条目。
	tsx := routeToolSet(t)
	tool := tsx.addIntent()
	raw := `{"intents":[{"summary":"a"},{"summary":"b"}],"route":{"family":"x"}}`
	res, err := tool.Call(context.Background(), json.RawMessage(raw), nil)
	if err != nil {
		t.Fatalf("add_intent 失败: %v", err)
	}
	if !res.IsError {
		t.Fatal("批量模式携带顶层 route 应报错")
	}
}

func TestOOBPollPersistsCorrelatedEvidenceAndContinuationBasis(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("oob continuation", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	planner := NewToolSet(ts, "planner")
	planner.SetTaskID(task.ID)
	created, failed := callIntent(t, planner, map[string]any{
		"summary": "验证自定义导入入口",
		"route": map[string]any{
			"entry":     "https://example.test/import",
			"family":    "ssrf",
			"component": "Custom Parser",
		},
	})
	if failed {
		t.Fatal(created)
	}
	intentID := parseCreatedIntentID(t, created)
	worker := NewToolSet(ts, "worker-1")
	worker.SetTaskID(task.ID)
	worker.SetOwnerNode(intentID)
	session := &fakeSession{url: "nonce.example.test"}
	session.interactions = []OOBInteraction{{
		Protocol: "dns",
		UniqueID: "probe-1",
		FullID:   "probe-1.nonce.example.test",
		Remote:   "192.0.2.10",
		Raw:      "A? probe-1.nonce.example.test",
	}}
	poll := registeredOOBPoll(t, worker, session, 1)
	result, err := poll.Call(context.Background(), json.RawMessage(`{"wait":1}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("oob_poll 失败: %v %s", err, result.Flatten())
	}
	output := decode(t, result.Flatten())
	factID := int64(output["fact_id"].(float64))
	fact, err := ts.GetNode(factID)
	if err != nil || fact == nil || fact.Kind != db.KindFact {
		t.Fatalf("回调证据应持久化为事实: %v %+v", err, fact)
	}
	var payload map[string]any
	if err := json.Unmarshal(fact.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["outcome"] != "progress" {
		t.Fatalf("事实结果状态错误: %v", payload)
	}
	if strings.Contains(string(fact.Payload), "private") || strings.Contains(string(fact.Payload), "session_key") {
		t.Fatalf("事实泄露会话秘密: %s", fact.Payload)
	}
	facts, err := ts.FactsYielded(intentID)
	if err != nil || len(facts) != 1 || facts[0] != factID {
		t.Fatalf("事实应关联到产生它的意图: %v %v", facts, err)
	}
	observation := routeObservationFact(t, planner, intentID, map[string]any{"summary": "recovered correlated callback", "evidence": "DNS A callback from 192.0.2.10 for the import trigger", "outcome": "progress"})
	continued, failed := callIntent(t, planner, map[string]any{
		"summary":    "用回调事实续探 SSRF 危害",
		"parent_ids": []int64{factID, observation},
		"route": map[string]any{
			"entry":     "https://EXAMPLE.test/import",
			"family":    "SSRF",
			"component": "custom-parser",
		},
	})
	if failed {
		t.Fatalf("有 OOB 新事实的续探被拒：%s", continued)
	}
}
