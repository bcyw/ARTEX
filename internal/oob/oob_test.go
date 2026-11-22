package oob

import (
	"crypto/tls"
	"io"
	"net/http"
	"testing"
)

// 票据 01 客户端接缝测试：配置默认值、安全传输、会话生命周期。
// 不连接公共 Interactsh 服务；只验证配置边界与真实客户端的构造/关闭路径。

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Fatal("默认应启用 OOB")
	}
	if cfg.ServerURL == "" {
		t.Fatal("默认应为公共官方服务")
	}
	if cfg.Token != "" {
		t.Fatal("默认公共服务无需 token")
	}
}

func TestSelfHostedConfigError(t *testing.T) {
	// 自建服务配置错误必须明确失败（票据要求：不回退公共服务、不静默降级）。
	if err := Validate(Config{Enabled: true, ServerURL: "127.0.0.1:8443", Token: "secret"}); err != nil {
		t.Fatalf("合法自建配置不应报错: %v", err)
	}
	if err := Validate(Config{Enabled: true, ServerURL: ""}); err == nil {
		t.Fatal("启用 OOB 但无服务地址应明确报错")
	}
	if err := Validate(Config{Enabled: true, ServerURL: "http://127.0.0.1:8443"}); err == nil {
		t.Fatal("启用 OOB 但使用明文 HTTP 应明确报错")
	}
}

func TestHTTPSOnly(t *testing.T) {
	cfg := Config{ServerURL: "https://oast.pro"}
	opts := clientOptionsFromConfig(cfg, &healthState{})
	if !opts.DisableHTTPFallback {
		t.Fatal("必须禁用 HTTP 明文降级")
	}
	if opts.ServerURL != cfg.ServerURL {
		t.Fatalf("ServerURL 透传失败: got %q", opts.ServerURL)
	}
	if opts.HTTPClient == nil || opts.HTTPClient.HTTPClient == nil || opts.HTTPClient.HTTPClient2 == nil {
		t.Fatal("必须使用受控 transport，而不是 SDK 默认的不校验证书客户端")
	}
	for i, hc := range []*http.Client{opts.HTTPClient.HTTPClient, opts.HTTPClient.HTTPClient2} {
		wrapped, ok := hc.Transport.(*healthTransport)
		if !ok {
			t.Fatalf("HTTP client %d 未包健康状态", i)
		}
		tr, ok := wrapped.base.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil {
			t.Fatalf("HTTP client %d 未配置 TLS transport", i)
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("HTTP client %d 仍跳过证书校验", i)
		}
		if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			t.Fatalf("HTTP client %d TLS 最低版本过低: %x", i, tr.TLSClientConfig.MinVersion)
		}
		if tr.DialTLS != nil || tr.DialTLSContext != nil {
			t.Fatalf("HTTP client %d 仍使用绕过 TLSClientConfig 的自定义拨号", i)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHealthTransportDistinguishesPollFailures(t *testing.T) {
	failing := &healthTransport{
		base:  roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }),
		state: &healthState{},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://oast.pro/poll?id=x", nil)
	if _, err := failing.RoundTrip(req); err == nil {
		t.Fatal("底层网络错误应透传")
	}
	n, err, at, _ := failing.state.snapshot()
	if n != 1 || err == nil || at.IsZero() {
		t.Fatalf("轮询网络错误应记录健康状态: n=%d err=%v at=%v", n, err, at)
	}

	badStatus := &healthTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: http.NoBody}, nil
		}),
		state: &healthState{},
	}
	if _, err := badStatus.RoundTrip(req); err != nil {
		t.Fatalf("HTTP 坏状态由健康层记录，不应透传错误: %v", err)
	}
	if n, err, _, _ := badStatus.state.snapshot(); n != 1 || err == nil {
		t.Fatalf("轮询 HTTP 失败应记录健康状态: n=%d err=%v", n, err)
	}

	healthy := &healthTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
		state: &healthState{},
	}
	if _, err := healthy.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if n, err, _, ok := healthy.state.snapshot(); n != 0 || err != nil || ok.IsZero() {
		t.Fatalf("成功轮询应记录观察窗口: n=%d err=%v ok=%v", n, err, ok)
	}
}

func TestClientLifecycle(t *testing.T) {
	// client.New 会立即向服务端注册；不可达的自建地址必须明确失败，
	// 不静默回退公共服务（票据 01：配置错误明确失败）。
	cfg := Config{Enabled: true, ServerURL: "https://127.0.0.1:1"}
	if _, err := NewClient(cfg); err == nil {
		t.Fatal("连接不可达服务应明确失败")
	}
	// nil 接收者的生命周期方法必须安全空操作。
	var s *Session
	if err := s.Close(); err != nil {
		t.Fatalf("nil Session Close 应安全: %v", err)
	}
	if err := s.StopPolling(); err != nil {
		t.Fatalf("nil Session StopPolling 应安全: %v", err)
	}
}
