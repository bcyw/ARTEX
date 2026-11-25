package oob

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

// The service speaks the real registration/poll/deregistration protocol. Its
// callbacks are fixture data; no DNS lookup or request to a target is performed.
type protocolFixture struct {
	mu                            sync.Mutex
	registration                  server.RegisterRequest
	response                      server.PollResponse
	registers, polls, deregisters int
	deregistered                  bool
	pollAfterClose                bool
	blockPath                     string
	blockAfter                    int
	entered                       chan struct{}
	blockOnce                     sync.Once
}

func (f *protocolFixture) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	f.mu.Lock()
	shouldBlock := r.URL.Path == f.blockPath && f.polls >= f.blockAfter
	f.mu.Unlock()
	if shouldBlock {
		_, _ = io.Copy(io.Discard, r.Body)
		f.blockOnce.Do(func() { close(f.entered) })
		<-r.Context().Done()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.TLS == nil || r.Header.Get("Authorization") != "fixture-token" {
		t.Error("request must use authenticated TLS")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/register":
		if err := json.NewDecoder(r.Body).Decode(&f.registration); err != nil {
			t.Error(err)
		}
		if f.registration.PublicKey == "" || f.registration.CorrelationID == "" || f.registration.SecretKey == "" {
			t.Error("registration missing protocol fields")
		}
		f.registers++
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	case "/poll":
		if r.URL.Query().Get("id") != f.registration.CorrelationID || r.URL.Query().Get("secret") != f.registration.SecretKey {
			t.Error("poll is not correlated to registered session")
		}
		f.polls++
		f.pollAfterClose = f.pollAfterClose || f.deregistered
		_ = json.NewEncoder(w).Encode(f.response)
		f.response = server.PollResponse{}
	case "/deregister":
		var req server.DeregisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.CorrelationID != f.registration.CorrelationID || req.SecretKey != f.registration.SecretKey {
			t.Error("deregister is not correlated to registered session")
		}
		f.deregisters++
		f.deregistered = true
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "deregistration successful"})
	default:
		t.Errorf("unexpected endpoint %s", r.URL.Path)
		http.NotFound(w, r)
	}
}

func newProtocolFixture(t *testing.T) (*protocolFixture, Config, *x509.CertPool) {
	t.Helper()
	f := &protocolFixture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return f, Config{Enabled: true, ServerURL: srv.URL, Token: "fixture-token"}, roots
}

func TestLocalTLSClientProtocolAndClose(t *testing.T) {
	f, cfg, roots := newProtocolFixture(t)
	if untrusted, err := NewClient(cfg); err == nil {
		_ = untrusted.Close()
		t.Fatal("untrusted local certificate must be rejected")
	}
	s, err := newClientWithRoots(cfg, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.StopPolling(); _ = s.Close() })
	first, second := s.URL(), s.URL()
	if first == "" || first == second {
		t.Fatalf("expected distinct full nonce addresses: %q %q", first, second)
	}
	stamp := time.Now().UTC()
	f.mu.Lock()
	correlation := f.registration.CorrelationID
	publicKey, err := storage.ParseB64RSAPublicKeyFromPEM(f.registration.PublicKey)
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, correlation) {
		t.Fatal("address must include registered correlation id")
	}
	plain, err := json.Marshal(server.Interaction{Protocol: "dns", UniqueID: correlation, FullId: first, Timestamp: stamp, RemoteAddress: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encrypted, err := storage.AESEncrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := json.Marshal(server.Interaction{Protocol: "http", UniqueID: correlation, FullId: second, Timestamp: stamp})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.response = server.PollResponse{Data: []string{encrypted}, AESKey: base64.StdEncoding.EncodeToString(wrappedKey), Extra: []string{string(extra)}}
	f.mu.Unlock()
	events := make(chan Interaction, 2)
	if err := s.StartPolling(5*time.Millisecond, func(it Interaction) { events <- it }); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{first, second} {
		select {
		case got := <-events:
			if got.FullID != want || !got.Timestamp.Equal(stamp) {
				t.Fatalf("wrong callback: %+v", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("real adapter did not deliver callback")
		}
	}
	// Close itself must stop the polling pump, once, even when callers race it
	// with explicit StopPolling or generation.
	if err := s.Close(); err != nil {
		t.Fatalf("close must stop polling before deregistration: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
	if got := s.URL(); got != "" {
		t.Fatalf("closed session still generates: %s", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registers != 1 || f.polls == 0 || f.deregisters != 1 || f.pollAfterClose {
		t.Fatalf("invalid protocol lifecycle: register=%d poll=%d deregister=%d poll-after-close=%v", f.registers, f.polls, f.deregisters, f.pollAfterClose)
	}
	// Shutdown can cancel the next tick. The decoded delivery must still be
	// recorded as a completed protocol poll, independently of that cancellation.
	if _, _, _, lastOK := s.Health(); lastOK.IsZero() {
		t.Fatal("decoded protocol poll was never recorded as complete")
	}
	serialized, err := json.Marshal(s)
	if err != nil || string(serialized) != "{}" {
		t.Fatalf("session keys must never serialize: %q %v", serialized, err)
	}
}

func TestLocalTLSRegistrationCancellation(t *testing.T) {
	f, cfg, roots := newProtocolFixture(t)
	f.blockPath, f.entered = "/register", make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		s, err := newClientContext(ctx, cfg, roots)
		if s != nil {
			_ = s.Close()
		}
		result <- err
	}()
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("registration did not reach local TLS server")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled registration returned a live session")
		}
	case <-time.After(time.Second):
		t.Fatal("registration ignored cancellation")
	}
}

func TestLocalTLSConcurrentCloseCancelsBlockedPoll(t *testing.T) {
	f, cfg, roots := newProtocolFixture(t)
	f.blockPath, f.entered = "/poll", make(chan struct{})
	s, err := newClientWithRoots(cfg, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.StartPolling(time.Millisecond, func(Interaction) {}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("poll did not reach local TLS server")
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Go(func() {
			<-start
			if i%3 == 0 {
				_ = s.URL()
			} else if i%3 == 1 {
				_ = s.StopPolling()
			} else if err := s.Close(); err != nil {
				t.Errorf("concurrent close: %v", err)
			}
		})
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close waited for blocked network poll")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deregisters != 1 || f.pollAfterClose {
		t.Fatalf("invalid concurrent close: deregister=%d poll-after-close=%v", f.deregisters, f.pollAfterClose)
	}
	if s.URL() != "" {
		t.Fatal("closed session issued a callback address")
	}
}

func TestLocalTLSInflightPollDoesNotReuseEarlierHealth(t *testing.T) {
	f, cfg, roots := newProtocolFixture(t)
	f.blockPath, f.blockAfter, f.entered = "/poll", 1, make(chan struct{})
	s, err := newClientWithRoots(cfg, roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.StartPolling(5*time.Millisecond, func(Interaction) {}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second poll did not reach local TLS server")
	}
	_, failure, _, lastOK := s.Health()
	if lastOK.IsZero() || failure == nil {
		t.Fatalf("in-flight poll cannot reuse earlier healthy response: lastOK=%v err=%v", lastOK, failure)
	}
}
