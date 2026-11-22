package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// 票据 01：真实 Interactsh 会话到 oobSession 接缝的适配器测试。
// 不连公共 Interactsh 服务；验证“注册失败明确报错”与唯一探测地址语义。

// fakeURLClient 是 urlClient 接口的替身，按序吐出预设主机名。
type fakeURLClient struct {
	urls []string
	i    int
}

func (f *fakeURLClient) URL() string {
	if f.i >= len(f.urls) {
		return ""
	}
	u := f.urls[f.i]
	f.i++
	return u
}

func (f *fakeURLClient) Close() error { return nil }

func TestInteractorGenerateUniqueProbes(t *testing.T) {
	// 用假 client 替身验证适配层的探测地址唯一性逻辑。
	f := &fakeURLClient{urls: []string{"u1.xxxx.oast.pro", "u2.xxxx.oast.pro", "u3.xxxx.oast.pro"}}
	it := &interactor{client: f}
	id1, host1, err := it.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id2, host2, err := it.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatalf("两次 Generate 应产出不同 probe_id: %s vs %s", id1, id2)
	}
	if host1 != "u1.xxxx.oast.pro" || host2 != "u2.xxxx.oast.pro" {
		t.Fatalf("探测地址透传失败: %s %s", host1, host2)
	}
	// probe_id 是主机名首段（完整 nonce 映射，不只靠 correlation ID 关联）。
	if got := strings.SplitN(host1, ".", 2)[0]; got != id1 {
		t.Fatalf("probe_id 应为主机名首段: id=%s host=%s", id1, host1)
	}
}

func TestInteractorNilSafety(t *testing.T) {
	var it *interactor
	if id, host, err := it.Generate(); err == nil || id != "" || host != "" {
		t.Fatalf("nil interactor Generate 应返回空: %q %q", id, host)
	}
	if err := it.Close(); err != nil {
		t.Fatalf("nil interactor Close 应安全: %v", err)
	}
}

func TestOOBDisabledByConfig(t *testing.T) {
	// 会话为 nil 时 worker 不应挂 oob_generate/oob_poll 工具（禁用/未装配即不存在）。
	if tools := oobTools(nil); len(tools) != 0 {
		t.Fatalf("无会话时应返回空工具集，got %d", len(tools))
	}
}

func TestProbeIDUsesFullCallbackHost(t *testing.T) {
	full := "c0ffeesessionnonce.example.test"
	if got := probeIDForInteraction(full, "A? unrelated.example.test"); got != "c0ffeesessionnonce" {
		t.Fatalf("应以完整回调主机名的首段关联探测，got %q", got)
	}
	if got := probeIDForInteraction("", "GET / HTTP/1.1\r\nHost: c0ffeesessionnonce.example.test\r\n\r\n"); got != "c0ffeesessionnonce" {
		t.Fatalf("FullId 缺失时应从原始请求回退取回调主机名，got %q", got)
	}
	if got := probeIDForInteraction("", ""); got != "" {
		t.Fatalf("无主机名时不得伪造 probe_id，got %q", got)
	}
}

func TestLiveSessionPollReportsServiceFailure(t *testing.T) {
	want := errors.New("poll failed")
	ls := &liveSession{
		it: interactor{client: &fakePollClient{}},
		health: func() (int64, error, time.Time, time.Time) {
			return 1, want, time.Now(), time.Time{}
		},
	}
	if _, got := ls.Poll(10 * time.Millisecond); !errors.Is(got, want) {
		t.Fatalf("轮询故障应返回错误而不是健康空窗口，got %v", got)
	}
}

func TestLiveSessionPollRequiresCompletedObservation(t *testing.T) {
	ls := &liveSession{
		it: interactor{client: &fakePollClient{}},
		health: func() (int64, error, time.Time, time.Time) {
			return 0, nil, time.Time{}, time.Time{}
		},
	}
	if _, err := ls.Poll(10 * time.Millisecond); !errors.Is(err, errNoCompletedPoll) {
		t.Fatalf("尚未完成观察必须明确为不可判断，got %v", err)
	}
	if err := ls.pollWindowHealth(time.Now().Add(-time.Second)); !errors.Is(err, errNoCompletedPoll) {
		t.Fatalf("没有完成轮询的窗口必须标识为未观察，got %v", err)
	}
}

func TestLiveSessionPollHealthyEmptyWindow(t *testing.T) {
	ls := &liveSession{
		it: interactor{client: &fakePollClient{}},
		health: func() (int64, error, time.Time, time.Time) {
			return 0, nil, time.Time{}, time.Now()
		},
	}
	its, err := ls.Poll(20 * time.Millisecond)
	if err != nil {
		t.Fatalf("健康空窗口不应报错: %v", err)
	}
	if len(its) != 0 {
		t.Fatalf("健康空窗口应返回空交互: %v", its)
	}
}

func TestLiveSessionPollIgnoresHistoricalFailure(t *testing.T) {
	historical := time.Now().Add(-time.Minute)
	ls := &liveSession{
		it: interactor{client: &fakePollClient{}},
		health: func() (int64, error, time.Time, time.Time) {
			return 3, errors.New("old failure"), historical, time.Now()
		},
	}
	if _, err := ls.Poll(10 * time.Millisecond); err != nil {
		t.Fatalf("历史错误不应污染当前健康窗口: %v", err)
	}
}

func TestLiveSessionPollReturnsCurrentWindowFailure(t *testing.T) {
	want := errors.New("poll failed")
	ls := &liveSession{
		it: interactor{client: &fakePollClient{}},
		health: func() (int64, error, time.Time, time.Time) {
			return 1, want, time.Now(), time.Now()
		},
	}
	if _, err := ls.Poll(10 * time.Millisecond); !errors.Is(err, want) {
		t.Fatalf("窗口内故障应报服务不可用，got %v", err)
	}
}
