// Package oob wraps the Interactsh client behind a narrow seam for ARTEX:
// configuration defaults, HTTPS-only transport, and per-worker-run session
// lifecycle. Private keys stay in memory only (never persisted to the DB,
// logs, or tool results).
package oob

import (
	"crypto/tls"
	"fmt"
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
	mu     sync.Mutex
	n      int64
	err    error
	lastAt time.Time
	lastOK time.Time
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

func (s *healthState) recordOK() {
	s.mu.Lock()
	s.lastOK = time.Now()
	s.err = nil
	s.mu.Unlock()
}

func (s *healthState) snapshot() (int64, error, time.Time, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n, s.err, s.lastAt, s.lastOK
}

type healthTransport struct {
	base  http.RoundTripper
	state *healthState
}

func (t *healthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	isPoll := strings.HasSuffix(strings.TrimRight(req.URL.Path, "/"), "/poll")
	if isPoll {
		if err != nil {
			t.state.record(err)
		} else if resp != nil && resp.StatusCode >= http.StatusBadRequest {
			t.state.record(fmt.Errorf("oob: 轮询返回 HTTP %d", resp.StatusCode))
		} else {
			t.state.recordOK()
		}
	}
	return resp, err
}

// clientOptionsFromConfig maps our Config to the official client's Options.
// HTTPS transport only: plaintext HTTP fallback is disabled and the transport
// verifies certificates (the SDK's default transport skips verification).
func clientOptionsFromConfig(c Config, health *healthState) client.Options {
	opts := retryablehttp.DefaultOptionsSpraying
	opts.Timeout = 10 * time.Second
	if health != nil {
		opts.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
			if tr, ok := base.(*http.Transport); ok {
				configureVerification(tr)
			}
			return &healthTransport{base: base, state: health}
		}
	}
	hc := retryablehttp.NewClient(opts)
	if health == nil {
		configureVerifiedTLS(hc.HTTPClient)
		configureVerifiedTLS(hc.HTTPClient2)
	}
	return client.Options{
		ServerURL:           c.ServerURL,
		Token:               c.Token,
		DisableHTTPFallback: true,
		HTTPClient:          hc,
	}
}

func configureVerifiedTLS(hc *http.Client) {
	if hc == nil {
		return
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		return
	}
	configureVerification(tr)
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
	client *client.Client
	health *healthState
}

// NewClient builds a live Interactsh session. The private key stays inside the
// client (in memory) — it is never serialized out by this package.
func NewClient(c Config) (*Session, error) {
	if err := Validate(c); err != nil {
		return nil, err
	}
	health := &healthState{}
	opts := clientOptionsFromConfig(c, health)
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
	return s.client.StartPolling(interval, func(i *server.Interaction) {
		cb(Interaction{
			Protocol:  i.Protocol,
			FullID:    i.FullId,
			Raw:       i.RawRequest,
			Remote:    i.RemoteAddress,
			Timestamp: i.Timestamp,
		})
	})
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
	return s.client.StopPolling()
}

// Close terminates the session. The private key is discarded with it.
func (s *Session) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}
