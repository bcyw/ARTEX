// Package oob wraps the Interactsh client behind a narrow seam for ARTEX:
// configuration defaults, HTTPS-only transport, and per-worker-run session
// lifecycle. Private keys stay in memory only (never persisted to the DB,
// logs, or tool results).
package oob

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// Config is the resolved OOB configuration. It comes from the on-disk config
// file (config.json "oob" block) with sane defaults: enabled, public official
// service. A self-hosted address is optional; a token is only used if set.
type Config struct {
	Enabled   bool   `json:"enabled"`
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

// DefaultConfig returns the shipped defaults: enabled against the public
// official Interactsh service. Per ticket 01 the operator may override with a
// self-hosted URL + token in config.json.
func DefaultConfig() Config {
	return Config{
		Enabled:   true,
		ServerURL: client.DefaultOptions.ServerURL,
		Token:     "",
	}
}

// Validate checks a Config for internal consistency. An enabled config with no
// server URL, or with a cleartext HTTP endpoint, is an error (fail loud, no
// silent fallback to another service or transport).
func Validate(c Config) error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.ServerURL) == "" {
		return fmt.Errorf("oob: 已启用但 server_url 为空；请配置自建地址或删除 oob 配置以使用默认公共服务")
	}
	for _, raw := range strings.Split(c.ServerURL, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return fmt.Errorf("oob: server_url 包含空地址")
		}
		if strings.HasPrefix(strings.ToLower(raw), "http://") {
			return fmt.Errorf("oob: 不允许明文 HTTP 服务地址 %q；请使用 HTTPS 或仅填写主机名", raw)
		}
	}
	return nil
}

// healthState records interaction-poll failures. The official Interactsh
// poller only logs them, which would otherwise make an outage indistinguishable
// from a healthy empty window; the agent reads this snapshot after each poll.
type healthState struct {
	mu          sync.Mutex
	n           int64
	err         error
	lastAt      time.Time
	lastOK      time.Time
	current     *pollDelivery
	inFlight    time.Time
	stopped     bool
	pollContext context.Context
	cancelPoll  context.CancelFunc
}

func (s *healthState) record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.n++
	s.err = err
	s.lastAt = time.Now()
	s.mu.Unlock()
}

func (s *healthState) snapshot() (int64, error, time.Time, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		return s.n, fmt.Errorf("oob: 轮询响应尚未处理完成"), s.current.started, s.lastOK
	}
	if !s.inFlight.IsZero() {
		return s.n, fmt.Errorf("oob: 轮询请求尚未完成"), s.inFlight, s.lastOK
	}
	return s.n, s.err, s.lastAt, s.lastOK
}

// The SDK logs decode/decrypt failures instead of exposing them. A poll is
// healthy only after its response has been consumed and every advertised
// interaction has reached the SDK callback, including encrypted Data entries.
type pollDelivery struct {
	started  time.Time
	expected int
	received int
}

func (s *healthState) delivered() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		s.current.received++
	}
}

type pollBody struct {
	io.ReadCloser
	state    *healthState
	delivery *pollDelivery
	once     sync.Once
}

func (b *pollBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		b.state.mu.Lock()
		defer b.state.mu.Unlock()
		if b.delivery.received != b.delivery.expected {
			b.state.n++
			b.state.err = fmt.Errorf("oob: 轮询交互未完整解码 (%d/%d)", b.delivery.received, b.delivery.expected)
			b.state.lastAt = time.Now()
		} else {
			b.state.lastOK = time.Now()
		}
		b.state.current = nil
	})
	return err
}

type healthTransport struct {
	base                http.RoundTripper
	state               *healthState
	registrationContext context.Context
}

func (t *healthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	isPoll := strings.HasSuffix(strings.TrimRight(req.URL.Path, "/"), "/poll")
	if t.registrationContext != nil && strings.HasSuffix(strings.TrimRight(req.URL.Path, "/"), "/register") {
		req = req.Clone(t.registrationContext)
	}
	if isPoll {
		t.state.mu.Lock()
		stopped := t.state.stopped
		pollContext := t.state.pollContext
		t.state.mu.Unlock()
		if stopped {
			return nil, fmt.Errorf("oob: 轮询已停止")
		}
		if pollContext != nil {
			ctx, cancel := context.WithCancel(req.Context())
			stop := context.AfterFunc(pollContext, cancel)
			defer stop()
			defer cancel()
			req = req.Clone(ctx)
		}
		t.state.mu.Lock()
		t.state.inFlight = time.Now()
		t.state.mu.Unlock()
		defer func() {
			t.state.mu.Lock()
			t.state.inFlight = time.Time{}
			t.state.mu.Unlock()
		}()
	}
	resp, err := base.RoundTrip(req)
	if isPoll {
		if err != nil {
			t.state.record(err)
		} else if resp != nil && resp.StatusCode != http.StatusOK {
			t.state.record(fmt.Errorf("oob: 轮询返回 HTTP %d", resp.StatusCode))
		} else {
			if resp == nil || resp.Body == nil {
				err = fmt.Errorf("oob: 轮询响应为空")
				t.state.record(err)
				return nil, err
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			var response *server.PollResponse
			if readErr == nil {
				readErr = json.Unmarshal(body, &response)
			}
			if readErr == nil && response != nil {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(body, &fields)
				if fields["data"] == nil && fields["extra"] == nil && fields["tlddata"] == nil {
					readErr = fmt.Errorf("oob: 响应缺少轮询协议字段")
				}
			}
			if readErr != nil || response == nil {
				err = fmt.Errorf("oob: 轮询响应未完整解码")
				t.state.record(err)
				return nil, err
			}
			delivery := &pollDelivery{started: time.Now(), expected: len(response.Data) + len(response.Extra)}
			for _, data := range response.TLDData {
				if data != "" {
					delivery.expected++
				}
			}
			t.state.mu.Lock()
			t.state.current = delivery
			t.state.mu.Unlock()
			resp.Body = &pollBody{ReadCloser: io.NopCloser(bytes.NewReader(body)), state: t.state, delivery: delivery}
		}
	}
	return resp, err
}

// clientOptionsFromConfig maps our Config to the official client's Options.
// HTTPS transport only: plaintext HTTP fallback is disabled and the transport
// verifies certificates (the SDK's default transport skips verification).
func clientOptionsFromConfig(c Config, health *healthState) client.Options {
	return clientOptionsWithRoots(context.Background(), c, health, nil)
}

func clientOptionsWithRoots(ctx context.Context, c Config, health *healthState, roots *x509.CertPool) client.Options {
	opts := retryablehttp.DefaultOptionsSpraying
	opts.Timeout = 10 * time.Second
	// The polling pump already retries on its next tick. SDK-internal backoff
	// cannot observe our run cancellation and would delay StopPolling/Close.
	opts.RetryMax = 0
	opts.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		if tr, ok := base.(*http.Transport); ok {
			configureVerification(tr)
			tr.TLSClientConfig.RootCAs = roots
		}
		if health != nil {
			return &healthTransport{base: base, state: health, registrationContext: ctx}
		}
		return base
	}
	hc := retryablehttp.NewClient(opts)
	return client.Options{
		ServerURL:           c.ServerURL,
		Token:               c.Token,
		DisableHTTPFallback: true,
		HTTPClient:          hc,
	}
}

func configureVerification(tr *http.Transport) {
	if tr == nil {
		return
	}
	// The SDK's ProjectDiscovery transport dials TLS itself, bypassing
	// TLSClientConfig. Drop those hooks so net/http performs a verified
	// handshake with the config below; plaintext dialing stays intact.
	tr.DialTLS = nil
	tr.DialTLSContext = nil
	cfg := tr.TLSClientConfig
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.InsecureSkipVerify = false
	cfg.MinVersion = tls.VersionTLS12
	tr.TLSClientConfig = cfg
}

// Session is one live Interactsh session scoped to a single worker run.
type Session struct {
	mu       sync.Mutex
	client   *client.Client
	health   *healthState
	polling  bool
	closed   bool
	closeErr error
}

// NewClient builds a live Interactsh session. The private key stays inside the
// client (in memory) — it is never serialized out by this package.
func NewClient(c Config) (*Session, error) {
	return NewClientContext(context.Background(), c)
}

// NewClientContext allows a cancelled run to interrupt lazy registration.
func NewClientContext(ctx context.Context, c Config) (*Session, error) {
	return newClientContext(ctx, c, nil)
}

// The trust-root seam lets local protocol fixtures use the production client
// with real certificate validation, without changing system trust or TLS policy.
func newClientWithRoots(c Config, roots *x509.CertPool) (*Session, error) {
	return newClientContext(context.Background(), c, roots)
}

func newClientContext(ctx context.Context, c Config, roots *x509.CertPool) (*Session, error) {
	if err := Validate(c); err != nil {
		return nil, err
	}
	health := &healthState{}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	opts := clientOptionsWithRoots(ctx, c, health, roots)
	cli, err := client.New(&opts)
	if err != nil {
		return nil, fmt.Errorf("oob: 创建 Interactsh 客户端失败: %w", err)
	}
	return &Session{client: cli, health: health}, nil
}

// URL returns the canonical interaction hostname for this session.
func (s *Session) URL() string {
	if s == nil || s.client == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ""
	}
	return s.client.URL()
}

// Interaction is the safe metadata subset of an Interactsh callback.
type Interaction struct {
	Protocol  string
	FullID    string
	Raw       string
	Remote    string
	Timestamp time.Time
}

// StartPolling registers a callback that fires for each interaction received.
// Polling runs until StopPolling is called; duration is the poll interval.
func (s *Session) StartPolling(interval time.Duration, cb func(Interaction)) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("oob: 会话未初始化")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("oob: 会话已关闭")
	}
	if s.polling {
		return fmt.Errorf("oob: 会话已在轮询")
	}
	if interval <= 0 {
		return fmt.Errorf("oob: 轮询间隔必须为正数")
	}
	s.health.mu.Lock()
	s.health.stopped = false
	s.health.pollContext, s.health.cancelPoll = context.WithCancel(context.Background())
	s.health.mu.Unlock()
	err := s.client.StartPolling(interval, func(i *server.Interaction) {
		s.health.delivered()
		cb(Interaction{
			Protocol:  i.Protocol,
			FullID:    i.FullId,
			Raw:       i.RawRequest,
			Remote:    i.RemoteAddress,
			Timestamp: i.Timestamp,
		})
	})
	s.polling = err == nil
	return err
}

// Health returns the cumulative poll-failure count, latest error, when that
// failure occurred, and when the last successful poll completed.
func (s *Session) Health() (int64, error, time.Time, time.Time) {
	if s == nil || s.client == nil {
		return 0, fmt.Errorf("oob: 会话未初始化"), time.Time{}, time.Time{}
	}
	if s.health == nil {
		return 0, nil, time.Time{}, time.Time{}
	}
	return s.health.snapshot()
}

// StopPolling halts the polling goroutine. Per the official client contract it
// must be called before Close on normal shutdown.
func (s *Session) StopPolling() error {
	if s == nil || s.client == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopPollingLocked()
}

func (s *Session) stopPollingLocked() error {
	if !s.polling {
		return nil
	}
	s.health.mu.Lock()
	s.health.stopped = true
	if s.health.cancelPoll != nil {
		s.health.cancelPoll()
	}
	s.health.mu.Unlock()
	s.polling = false
	return s.client.StopPolling()
}

// Close terminates the session. The private key is discarded with it.
func (s *Session) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	stopErr := s.stopPollingLocked()
	s.closeErr = errors.Join(stopErr, s.client.Close())
	return s.closeErr
}
