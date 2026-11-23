package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/internal/oob"
)

// 票据 04：OOB 去重、并发隔离、异常重启、秘密保护与不可用提示。
// 全部通过既有 oobSession / liveSession / 工具层接缝验证，不连真实服务。

// prefixSession 派生 fakeSession，但让 probe_id 按前缀区分，模拟不同 run
// 的独立会话地址。
type prefixSession struct {
	*fakeSession
	prefix string
}

func (p *prefixSession) Generate() (string, string, error) {
	if p.fakeSession.generateErr != nil {
		return "", "", p.fakeSession.generateErr
	}
	return p.prefix, p.fakeSession.url, nil
}

// deliverFake 是可注入交互的会话替身：delay 后投递 interactions（每条可能
// 重复投递 dedup 次），用于驱动 liveSession 的轮询泵回调。
type deliverFake struct {
	url          string
	interactions []oob.Interaction
	dedup        int
	delay        time.Duration
	delivered    int
}

func (f *deliverFake) URL() string  { return f.url }
func (f *deliverFake) Close() error { return nil }
func (f *deliverFake) StartPolling(_ time.Duration, cb func(oob.Interaction)) error {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	for i := 0; i < len(f.interactions); i++ {
		for r := 0; r < f.dedup; r++ {
			cb(f.interactions[i])
		}
	}
	return nil
}
func (f *deliverFake) StopPolling() error { return nil }
func (f *deliverFake) Health() (int64, error, time.Time, time.Time) {
	return 0, nil, time.Time{}, time.Now()
}

// fakeOobSession 是 *oob.Session 的最小替身，供 newLiveSession 使用。
func newDeliverLive(t *testing.T, f *deliverFake) *liveSession {
	t.Helper()
	ls, err := newLiveSessionFrom(f, f, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("newLiveSessionFrom: %v", err)
	}
	return ls
}

func TestLiveSessionDedupsRepeatedInteractions(t *testing.T) {
	// Interactsh 可能重复投递同一事件；同一事件只应入队一次。
	f := &deliverFake{
		url: "xxxx.oast.pro",
		interactions: []oob.Interaction{
			{Protocol: "dns", FullID: "p1.xxxx.oast.pro", Raw: "A? p1.xxxx.oast.pro", Remote: "192.0.2.1"},
			{Protocol: "http", FullID: "p2.xxxx.oast.pro", Raw: "GET / HTTP/1.1\r\nHost: p2.xxxx.oast.pro", Remote: "192.0.2.2"},
		},
		dedup: 3,
	}
	ls := newDeliverLive(t, f)
	defer func() { _ = ls.Close() }()
	its, err := ls.Poll(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(its) != 2 {
		t.Fatalf("重复投递应去重为 2 条，got %d: %+v", len(its), its)
	}
	if its[0].UniqueID == its[1].UniqueID {
		t.Fatalf("两条不同探测被折叠: %+v", its)
	}
	// 再次 Poll 不应吐出旧事件。
	again, err := ls.Poll(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("已取走的事件不应重复返回: %+v", again)
	}
}

func TestSessionsAreIsolatedPerFactoryCall(t *testing.T) {
	// 多 worker：工厂每次调用返回独立会话，地址互不相同，事件不串。
	var mu sync.Mutex
	n := 0
	newSess := func() (oobSession, func(), error) {
		mu.Lock()
		n++
		i := n
		mu.Unlock()
		fs := &fakeSession{url: "run" + strings.Repeat("x", i) + ".oast.pro"}
		id := "u" + strings.Repeat("n", i)
		return &prefixSession{fakeSession: fs, prefix: id}, func() {}, nil
	}
	s1, c1, err := newSess()
	if err != nil {
		t.Fatal(err)
	}
	s2, c2, err := newSess()
	if err != nil {
		t.Fatal(err)
	}
	defer c1()
	defer c2()
	id1, host1, _ := s1.Generate()
	id2, host2, _ := s2.Generate()
	if id1 == id2 || host1 == host2 {
		t.Fatalf("不同 run 的会话应产出不同探测地址: %s vs %s", host1, host2)
	}
}

func TestClosedSessionNotReusableAfterRestart(t *testing.T) {
	// 异常重启语义：关闭后的会话不可复用——Generate 明确失败，不伪造旧地址。
	f := &deliverFake{url: "xxxx.oast.pro"}
	ls := newDeliverLive(t, f)
	if err := ls.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ls.Close(); err != nil {
		t.Fatalf("重复 Close 应幂等: %v", err)
	}
	if _, _, err := ls.Generate(); err == nil {
		t.Fatal("关闭后的会话 Generate 必须失败，不得伪称仍活跃")
	}
	if _, err := ls.Poll(10 * time.Millisecond); !errors.Is(err, errSessionClosed) {
		t.Fatalf("关闭后的会话 Poll 应报会话已关闭，got %v", err)
	}
	// 工厂层：lazySession 关闭后 ensure 必须失败（新 run 分配新地址）。
	lz := newLazySession(oob.Config{Enabled: true, ServerURL: "oast.pro"})
	if err := lz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lz.Generate(); err == nil {
		t.Fatal("lazySession 关闭后 Generate 必须失败")
	}
}

func TestOOBPollServiceUnavailableHintsSelfHost(t *testing.T) {
	// 公共服务故障的提示语应包含自建/重试建议。
	fs := &fakeSession{url: "xxxx.oast.pro", err: context.DeadlineExceeded}
	res, err := (&ToolSet{}).oobPoll(fs).Call(t.Context(), json.RawMessage(`{"wait":1}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("服务不可用应作为明确结果返回: %v %s", err, res.Flatten())
	}
	hint, _ := decode(t, res.Flatten())["hint"].(string)
	if !strings.Contains(hint, "自建") && !strings.Contains(hint, "重试") {
		t.Fatalf("service_unavailable 应提示自建服务或稍后重试，got %q", hint)
	}
}

func TestOOBFactOmitsRawInteractionBody(t *testing.T) {
	// 仅保存回调元数据；原始报文里的敏感内容不写入事实 payload。
	d := testDB(t)
	t.Cleanup(func() { d.Close() })
	task, err := d.CreateTask("oob privacy", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	ts := d.Exploration(task.ExplorationID)
	worker := NewToolSet(ts, "worker-1")
	worker.SetTaskID(task.ID)
	intentID, err := ts.AddIntent(map[string]any{"summary": "OOB 隐私"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	worker.SetOwnerNode(intentID)
	fs := &fakeSession{url: "xxxx.oast.pro", interactions: []OOBInteraction{{
		Protocol: "dns", UniqueID: "p1", FullID: "p1.xxxx.oast.pro",
		Remote: "192.0.2.1", Raw: "A? p1.xxxx.oast.pro CLASSIFIED-INTERNAL-DATA",
	}}}
	res, err := worker.oobPoll(fs).Call(t.Context(), json.RawMessage(`{"wait":1}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("oob_poll 失败: %v %s", err, res.Flatten())
	}
	factID := int64(decode(t, res.Flatten())["fact_id"].(float64))
	fact, err := ts.GetNode(factID)
	if err != nil || fact == nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fact.Payload), "CLASSIFIED-INTERNAL-DATA") {
		t.Fatalf("事实 payload 不得包含原始报文敏感内容: %s", fact.Payload)
	}
}
