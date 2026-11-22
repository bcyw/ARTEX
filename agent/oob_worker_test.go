package agent

import (
	"testing"
	"time"
)

// 票据 01：worker per-run OOB 会话装配测试（模型替身，不连真实服务）。

func TestWorkerOOBToolsPerRun(t *testing.T) {
	w := &Worker{}
	if w.oobFactory != nil {
		t.Fatal("默认无 OOB 工厂")
	}
	// SetOOBSessionFactory 装配工厂；每个 run 调一次，返回会话 + 清理函数。
	calls := 0
	w.SetOOBSessionFactory(func() (oobSession, func(), error) {
		calls++
		fs := &fakeSession{url: "xxxx.oast.pro"}
		return fs, func() {}, nil
	})
	sess, cleanup, err := w.oobFactory()
	if err != nil || sess == nil || cleanup == nil {
		t.Fatalf("工厂应返回会话与清理函数: %v", err)
	}
	cleanup()
	if calls != 1 {
		t.Fatalf("工厂应被调用一次，got %d", calls)
	}
}

func TestWorkerOOBSessionCloseOrder(t *testing.T) {
	// liveSession 关闭次序：先 StopPolling 再 Close（官方客户端契约）。
	var order []string
	ls := &liveSession{it: interactor{client: &fakePollClient{onStop: func() { order = append(order, "stop") }, onClose: func() { order = append(order, "close") }}}}
	if err := ls.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if len(order) != 2 || order[0] != "stop" || order[1] != "close" {
		t.Fatalf("关闭次序应为 stop→close，got %v", order)
	}
}

func TestOOBPollBoundedWait(t *testing.T) {
	// 有界等待：无回调时 Poll 应在 wait 到期后返回空，不永久阻塞。
	ls := &liveSession{it: interactor{client: &fakePollClient{}}}
	start := time.Now()
	its, err := ls.Poll(300 * time.Millisecond)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if len(its) != 0 {
		t.Fatalf("无回调应返回空: %v", its)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("有界等待应遵守 deadline，耗时 %v", el)
	}
}

// fakePollClient 是 urlClient + StopPolling 的替身。
type fakePollClient struct {
	onStop  func()
	onClose func()
}

func (f *fakePollClient) URL() string { return "u1.xxxx.oast.pro" }
func (f *fakePollClient) StopPolling() error {
	if f.onStop != nil {
		f.onStop()
	}
	return nil
}
func (f *fakePollClient) Close() error {
	if f.onClose != nil {
		f.onClose()
	}
	return nil
}
