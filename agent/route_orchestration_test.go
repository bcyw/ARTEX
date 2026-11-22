package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// 票 02：主 planner/worker 编排入口的确定性测试。模型替身只发出固定工具调用，
// OOB 服务用 fakeSession；这里证明路线创建、带外事实、信息增量续探与停止条件
// 能在真实 Plan/Execute 路径上协同，不证明真实模型效果或真实目标检出率。

type scriptedTurn struct {
	events []llm.StreamEvent
}

type scriptedProvider struct {
	mu             sync.Mutex
	turns          []scriptedTurn
	next           int
	reqs           []llm.CompletionRequest
	lastToolResult string
}

func (p *scriptedProvider) add(events ...llm.StreamEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.turns = append(p.turns, scriptedTurn{events: events})
}

func (p *scriptedProvider) requestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reqs)
}

func (p *scriptedProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	for i := len(req.Messages) - 1; i >= 0; i-- {
		for j := len(req.Messages[i].Content) - 1; j >= 0; j-- {
			block := req.Messages[i].Content[j]
			if block.Type == llm.BlockToolResult {
				p.lastToolResult = ""
				for _, c := range block.Content {
					p.lastToolResult += c.Text
				}
				i = -1
				break
			}
		}
	}
	if p.next >= len(p.turns) {
		return func(yield func(llm.StreamEvent, error) bool) {
			yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
		}
	}
	events := p.turns[p.next].events
	p.next++
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (p *scriptedProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func toolTurn(id, name string, input any) []llm.StreamEvent {
	raw, _ := json.Marshal(input)
	return []llm.StreamEvent{
		{Type: llm.SEToolUseStart, ToolID: id, ToolName: name},
		{Type: llm.SEToolInputJSON, Text: string(raw)},
		{Type: llm.SEMessageDelta, StopReason: "tool_use"},
		{Type: llm.SEMessageStop},
	}
}

func textTurn(text string) []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: text},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
		{Type: llm.SEMessageStop},
	}
}

func routeIntentPayload(t *testing.T, ts *db.ExplorationStore, id int64) map[string]any {
	t.Helper()
	n, err := ts.GetNode(id)
	if err != nil || n == nil {
		t.Fatalf("读取意图 %d 失败: %v", id, err)
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func oobFactFrom(t *testing.T, ts *db.ExplorationStore, intentID int64) (int64, map[string]any) {
	t.Helper()
	ids, err := ts.FactsYielded(intentID)
	if err != nil || len(ids) == 0 {
		t.Fatalf("意图 %d 未产生 OOB 事实: %v %v", intentID, ids, err)
	}
	n, err := ts.GetNode(ids[0])
	if err != nil || n == nil {
		t.Fatalf("读取 OOB 事实 %d 失败: %v", ids[0], err)
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return ids[0], p
}

func TestRouteOrchestrationOOBEvidenceContinuesOnceThenStops(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("route orchestration", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	workDir := t.TempDir()

	provider := &scriptedProvider{}
	route := map[string]any{
		"entry":         "https://example.test/import",
		"family":        "deserialization",
		"component":     "custom-parser",
		"parameter":     "payload",
		"prerequisites": []string{"user-controlled payload reaches parser"},
		"hypothesis":    "parser resolves external callbacks",
		"next_step":     "deliver DNS gadget and poll OOB",
		"tested":        []string{"baseline"},
		"remaining":     []string{"dns gadget"},
	}
	provider.add(toolTurn("p1", "add_intent", map[string]any{
		"summary": "验证自定义反序列化入口",
		"route":   route,
	})...)
	provider.add(textTurn("路线已创建")...)

	planner := NewPlanner(provider, "test-model", workDir, nil, 0, 6)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner 第一轮失败: %v", err)
	}
	intents, err := ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("第一轮应创建一条路线意图: %v %v", intents, err)
	}
	firstIntent := intents[0]
	if p := routeIntentPayload(t, ts, firstIntent.ID); p["route"] == nil {
		t.Fatalf("路线未落库: %+v", p)
	}

	provider.add(toolTurn("w1", "oob_generate", map[string]any{"count": 1})...)
	provider.add(toolTurn("w2", "oob_poll", map[string]any{"wait": 1})...)
	provider.add(textTurn("收到带外回调，已记录事实")...)
	session := &fakeSession{url: "nonce.example.test"}
	session.interactions = []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1", Remote: "198.51.100.9"}}
	worker := NewWorker(provider, "test-model", workDir, nil, 0, 6)
	sessionCreates, sessionCleanups := 0, 0
	worker.SetOOBSessionFactory(func() (oobSession, func(), error) {
		sessionCreates++
		return session, func() { sessionCleanups++ }, nil
	})
	if _, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, ts, firstIntent, nil, nil, nil, nil); err != nil {
		t.Fatalf("worker 执行失败: %v", err)
	}
	if got := len(session.generated); got != 1 {
		t.Fatalf("worker 应生成一次 OOB 地址，got %d", got)
	}
	if sessionCreates != 1 || sessionCleanups != 1 {
		t.Fatalf("每个 worker run 应创建并清理一次 OOB 会话，got create=%d cleanup=%d", sessionCreates, sessionCleanups)
	}
	if err := ts.SetIntentState(firstIntent.ID, "done"); err != nil {
		t.Fatal(err)
	}
	oobFactID, oobPayload := oobFactFrom(t, ts, firstIntent.ID)
	if oobPayload["outcome"] != "progress" {
		t.Fatalf("回调事实应为 progress: %+v", oobPayload)
	}

	continuedRoute := map[string]any{
		"entry":         "https://EXAMPLE.test/import?url=next",
		"family":        "DESERIALIZATION",
		"component":     "CUSTOM-PARSER",
		"parameter":     "payload",
		"prerequisites": []string{"user-controlled payload reaches parser"},
		"hypothesis":    "回连已确认，继续升级到命令执行",
		"next_step":     "deliver HTTP gadget and request internal content",
		"tested":        []string{"baseline", "dns-gadget"},
		"remaining":     []string{"http gadget"},
	}
	provider.add(toolTurn("p2", "add_intent", map[string]any{
		"summary":    "用 OOB 事实续探反序列化危害",
		"parent_ids": []int64{oobFactID},
		"route":      continuedRoute,
	})...)
	provider.add(textTurn("已续探一次")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner 第二轮失败: %v", err)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 2 {
		t.Fatalf("OOB 新事实应允许一次续探，意图数=%d err=%v", len(intents), err)
	}
	secondID := intents[0].ID
	if secondID == firstIntent.ID {
		t.Fatalf("第二轮应创建新的续探意图")
	}
	second := intents[0]
	provider.add(toolTurn("w3", "oob_poll", map[string]any{"wait": 1})...)
	provider.add(textTurn("续探已执行并按证据停止")...)
	continuedSession := &fakeSession{url: "nonce.example.test"}
	worker2 := NewWorker(provider, "test-model", workDir, nil, 0, 6)
	worker2.SetOOBSessionFactory(func() (oobSession, func(), error) {
		return continuedSession, func() {}, nil
	})
	if _, _, err := worker2.Execute(t.Context(), "worker-2", task.ID, nil, ts, second, nil, nil, nil, nil); err != nil {
		t.Fatalf("第二意图执行失败: %v", err)
	}
	if got := len(continuedSession.generated); got != 0 {
		t.Fatalf("续探应复用事实而不是重复生成地址，got %d", got)
	}
	if err := ts.SetIntentState(secondID, "done"); err != nil {
		t.Fatal(err)
	}

	// 不改 tested、不提供新 parent：即使换 summary/next_step 也必须被拒。
	provider.add(toolTurn("p3", "add_intent", map[string]any{
		"summary": "第三次换措辞重复同一 payload",
		"route": map[string]any{
			"entry":     "https://example.test/import",
			"family":    "deserialization",
			"component": "custom-parser",
			"parameter": "payload",
			"next_step": "再次投递相同 DNS gadget",
			"tested":    []string{"baseline", "dns-gadget"},
		},
	})...)
	provider.add(textTurn("原样重试")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner 第三轮失败: %v", err)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 2 {
		t.Fatalf("无新增事实/变体的重复意图应被拒绝，意图数=%d err=%v", len(intents), err)
	}
	// planner 的拒绝是工具结果；模型后续仍应收到一次拒绝反馈并正常结束，
	// 而不是把工具错误当成 Go error 中断整轮规划。
	if provider.requestCount() == 0 {
		t.Fatal("脚本 provider 未收到任何请求")
	}
	if !strings.Contains(provider.lastToolResult, "不算信息增量") {
		t.Fatalf("重复路线意图应带明确拒绝原因，got %q", provider.lastToolResult)
	}
}

func TestRouteOrchestrationImpactStopsContinuation(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("route impact stop", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	workDir := t.TempDir()
	route := map[string]any{
		"entry":     "https://example.test/upload",
		"family":    "file_upload",
		"component": "custom-uploader",
	}
	provider := &scriptedProvider{}
	provider.add(toolTurn("p1", "add_intent", map[string]any{"summary": "验证上传链", "route": route})...)
	provider.add(textTurn("路线已创建")...)
	planner := NewPlanner(provider, "test-model", workDir, nil, 0, 6)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intents, err := ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("应创建一条意图: %v %v", intents, err)
	}
	firstID := intents[0].ID
	impact := map[string]any{
		"summary":    "上传链已证实命令执行",
		"confidence": "observed",
		"route": map[string]any{
			"entry":     "https://example.test/upload",
			"family":    "file_upload",
			"component": "custom-uploader",
			"outcome":   "impact",
			"reason":    "webshell 已执行",
		},
	}
	raw, _ := json.Marshal(impact)
	result, err := NewToolSet(ts, "worker-1").recordFact().Call(t.Context(), raw, nil)
	if err != nil || result.IsError {
		t.Fatalf("记录 impact 失败: %v %s", err, result.Flatten())
	}
	if err := ts.SetIntentState(firstID, "done"); err != nil {
		t.Fatal(err)
	}
	provider.add(toolTurn("p2", "add_intent", map[string]any{
		"summary": "危害已证实后再试一次",
		"route":   map[string]any{"entry": "https://example.test/upload", "family": "file_upload", "component": "custom-uploader", "next_step": "另一个绕过"},
	})...)
	provider.add(textTurn("尝试续探")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatalf("planner 第二轮失败: %v", err)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("impact 后不得再建同路线意图，意图数=%d err=%v", len(intents), err)
	}
	states := NewToolSet(ts, "planner").routeStates()
	state := states[routeIdentity("https://example.test/upload", "file_upload", "custom-uploader", "")]
	if state == nil || !state.Stopped || state.Outcome != "impact" {
		t.Fatalf("impact 停止状态未恢复: %+v", state)
	}
}

func TestRouteOrchestrationNoInteractionDoesNotRetryWorker(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("route no interaction", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	workDir := t.TempDir()
	route := map[string]any{"entry": "https://example.test/import", "family": "ssrf", "component": "custom-fetcher"}
	provider := &scriptedProvider{}
	provider.add(toolTurn("p1", "add_intent", map[string]any{"summary": "SSRF 路线", "route": route})...)
	provider.add(textTurn("路线已创建")...)
	planner := NewPlanner(provider, "test-model", workDir, nil, 0, 6)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intents, err := ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("应创建一条意图: %v %v", intents, err)
	}
	firstIntent := intents[0]
	provider.add(toolTurn("w1", "oob_generate", map[string]any{"count": 1})...)
	provider.add(toolTurn("w2", "oob_poll", map[string]any{"wait": 1})...)
	provider.add(textTurn("健康空窗口，已记录 no_interaction")...)
	worker := NewWorker(provider, "test-model", workDir, nil, 0, 6)
	sessionCreates := 0
	worker.SetOOBSessionFactory(func() (oobSession, func(), error) {
		sessionCreates++
		return &fakeSession{url: "nonce.example.test"}, func() {}, nil
	})
	if _, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, ts, firstIntent, nil, nil, nil, nil); err != nil {
		t.Fatalf("worker 执行失败: %v", err)
	}
	if sessionCreates != 1 {
		t.Fatalf("健康空窗口不应自动重跑 worker，OOB 会话创建次数=%d", sessionCreates)
	}
	if err := ts.SetIntentState(firstIntent.ID, "done"); err != nil {
		t.Fatal(err)
	}
	oobFactID, oobPayload := oobFactFrom(t, ts, firstIntent.ID)
	if oobPayload["outcome"] != "no_interaction" {
		t.Fatalf("健康空窗口应保留 no_interaction: %+v", oobPayload)
	}
	provider.add(toolTurn("p2", "add_intent", map[string]any{
		"summary":    "空窗口后重跑同一 payload",
		"parent_ids": []int64{oobFactID},
		"route":      map[string]any{"entry": "https://example.test/import", "family": "ssrf", "component": "custom-fetcher", "next_step": "重跑"},
	})...)
	provider.add(textTurn("尝试重跑")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("no_interaction 不得触发自动重跑，意图数=%d err=%v", len(intents), err)
	}
	if sessionCreates != 1 {
		t.Fatalf("规划轮不应重开 OOB 会话，got %d", sessionCreates)
	}
}

func TestRouteOrchestrationOriginalIntentContinuesThenStops(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("route original continuation", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	workDir := t.TempDir()

	route := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "deserialization",
		"component": "custom-parser",
		"tested":    []string{"baseline"},
	}
	provider := &scriptedProvider{}
	provider.add(toolTurn("p1", "add_intent", map[string]any{"summary": "建立路线", "route": route})...)
	provider.add(textTurn("路线已建立")...)
	planner := NewPlanner(provider, "test-model", workDir, nil, 0, 6)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intents, err := ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("应创建一条路线意图: %v %v", intents, err)
	}
	original := intents[0]

	provider.add(toolTurn("w1", "oob_generate", map[string]any{"count": 1})...)
	provider.add(toolTurn("w2", "oob_poll", map[string]any{"wait": 1})...)
	provider.add(textTurn("收到回调")...)
	session := &fakeSession{url: "nonce.example.test"}
	session.interactions = []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1", Remote: "198.51.100.9"}}
	worker := NewWorker(provider, "test-model", workDir, nil, 0, 6)
	worker.SetOOBSessionFactory(func() (oobSession, func(), error) { return session, func() {}, nil })
	if _, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, ts, original, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := ts.SetIntentState(original.ID, "done"); err != nil {
		t.Fatal(err)
	}
	oobFactID, _ := oobFactFrom(t, ts, original.ID)

	provider.add(toolTurn("p2", "continue_intent", map[string]any{
		"intent_id":  original.ID,
		"message":    "回调已确认，继续升级到命令执行",
		"parent_ids": []int64{oobFactID},
		"route":      route,
	})...)
	provider.add(textTurn("通过原意图续跑")...)
	continued := 0
	planner.SetContinueWork(func(intentID int64, msg string) error {
		continued++
		if _, err := ts.CompareAndSetIntentState(intentID, "paused", "running"); err != nil {
			return err
		}
		node, err := ts.GetNode(intentID)
		if err != nil || node == nil {
			return fmt.Errorf("读取续跑意图失败: %w", err)
		}
		impact := map[string]any{
			"summary":    "续跑证实命令执行",
			"confidence": "observed",
			"intent_id":  intentID,
			"route": map[string]any{
				"entry":     "https://example.test/import",
				"family":    "deserialization",
				"component": "custom-parser",
				"outcome":   "impact",
			},
		}
		raw, _ := json.Marshal(impact)
		if res, err := NewToolSet(ts, "worker-2").recordFact().Call(t.Context(), raw, nil); err != nil || res.IsError {
			return fmt.Errorf("续跑记录影响失败: %v %s", err, res.Flatten())
		}
		if _, _, err := worker.ExecuteWithMessage(t.Context(), "worker-2", task.ID, nil, ts, node, nil, nil, nil, nil, "req-1", msg); err != nil {
			return err
		}
		return ts.SetIntentState(intentID, "done")
	})
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	if continued != 1 {
		t.Fatalf("planner 应通过现有 worker 续跑一次，got %d", continued)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("原意图续跑不应新建意图，意图数=%d err=%v", len(intents), err)
	}
	state := NewToolSet(ts, "planner").routeStates()[routeIdentity("https://example.test/import", "deserialization", "custom-parser", "")]
	if state == nil || !state.Stopped || state.Outcome != "impact" {
		t.Fatalf("续跑后的 impact 应停止路线: %+v", state)
	}

	provider.add(toolTurn("p3", "add_intent", map[string]any{"summary": "影响后再换词重试", "route": route})...)
	provider.add(textTurn("按停止条件收手")...)
	if _, _, err := planner.Plan(t.Context(), task.ID, nil, ts, task.Goal, nil, nil); err != nil {
		t.Fatal(err)
	}
	intents, err = ts.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 {
		t.Fatalf("已证实影响后不得再建同路线意图，意图数=%d err=%v", len(intents), err)
	}
	if !strings.Contains(provider.lastToolResult, "已确定停止") {
		t.Fatalf("停止原因应回传模型，got %q", provider.lastToolResult)
	}
}

func TestWorkerOOBUnavailableIsExplicitAndNonBlocking(t *testing.T) {
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("oob unavailable", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	intentID, err := ts.AddIntent(map[string]any{"summary": "不需要 OOB 的本地检查"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(intentID)
	if err != nil || intent == nil {
		t.Fatal(err)
	}
	provider := &scriptedProvider{}
	provider.add(textTurn("本地检查完成")...)
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 6)
	calls := 0
	worker.SetOOBSessionFactory(func() (oobSession, func(), error) {
		calls++
		return nil, nil, errors.New("OOB 服务配置错误")
	})
	terminal, _, err := worker.Execute(t.Context(), "worker-1", task.ID, nil, ts, intent, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("OOB 装配失败不应中断 worker: %v", err)
	}
	if terminal == "" {
		t.Fatal("worker 应正常结束")
	}
	if calls != 1 {
		t.Fatalf("OOB 工厂每 run 只调用一次，got %d", calls)
	}
	if provider.requestCount() != 1 {
		t.Fatalf("worker 应正常请求模型一次，got %d", provider.requestCount())
	}
	req := provider.reqs[0]
	system := strings.Join(req.System, "\n")
	if !strings.Contains(system, "OOB 不可用") {
		t.Fatalf("系统提示应明确 OOB 不可用: %q", system)
	}
	if strings.Contains(system, "先 oob_generate") {
		t.Fatalf("OOB 不可用时不得宣传 OOB 工具: %q", system)
	}
	for _, tool := range req.Tools {
		if tool.Name == "oob_generate" || tool.Name == "oob_poll" {
			t.Fatalf("OOB 装配失败时不应暴露 %s", tool.Name)
		}
	}
}
