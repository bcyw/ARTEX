package report

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeRequestProducesReplayablePacket(t *testing.T) {
	head := "POST /api/x?y=1 HTTP/1.1\nHost: a.example.com\nContent-Length: 999\nTransfer-Encoding: chunked\nContent-Type: application/json"
	body := []byte(`{"a":1}`)

	got, ok := NormalizeRequest(head, body, "https://a.example.com/api/x")
	if !ok {
		t.Fatal("expected replayable packet")
	}
	for _, want := range []string{
		"POST /api/x?y=1 HTTP/1.1\r\n",
		"Host: a.example.com\r\n",
		"Content-Type: application/json\r\n",
		"Content-Length: 7\r\n",
		"\r\n\r\n{\"a\":1}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%q", want, got)
		}
	}
	if strings.Contains(got, "Transfer-Encoding") || strings.Contains(got, "999") {
		t.Errorf("stale framing headers must be dropped:\n%s", got)
	}
}

func TestNormalizeRequestAddsMissingHost(t *testing.T) {
	got, ok := NormalizeRequest("GET /a HTTP/1.1\nUser-Agent: x", nil, "https://api.example.com:8443/a")
	if !ok {
		t.Fatal("expected replayable packet")
	}
	if !strings.Contains(got, "Host: api.example.com:8443\r\n") {
		t.Errorf("host must be inserted after the request line:\n%s", got)
	}
	if !strings.HasPrefix(got, "GET /a HTTP/1.1\r\nHost: ") {
		t.Errorf("host must come first:\n%s", got)
	}
}

func TestNormalizeRequestDecodesGzipAndRewritesFraming(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"ok":true}`))
	_ = zw.Close()

	head := "POST /a HTTP/1.1\nHost: h\nContent-Encoding: gzip\nContent-Length: " + strconv.Itoa(buf.Len())
	got, ok := NormalizeRequest(head, buf.Bytes(), "https://h/a")
	if !ok {
		t.Fatal("expected gzip body to be decoded")
	}
	if strings.Contains(got, "Content-Encoding") {
		t.Errorf("decoded packet must not keep Content-Encoding:\n%s", got)
	}
	if !strings.Contains(got, "Content-Length: 11\r\n") {
		t.Errorf("length must match the decoded body:\n%s", got)
	}
	if !strings.Contains(got, `{"ok":true}`) {
		t.Errorf("decoded body missing:\n%s", got)
	}
}

func TestNormalizeRequestRejectsBinaryBody(t *testing.T) {
	if _, ok := NormalizeRequest("POST /a HTTP/1.1\nHost: h", []byte{0x00, 0x01, 0x02, 0xff}, ""); ok {
		t.Fatal("binary body must not be rendered as text")
	}
}

func TestNormalizeResponseKeepsCapturedStatusLine(t *testing.T) {
	got, ok := NormalizeResponse("HTTP 200\nContent-Type: application/json\nContent-Length: 2", []byte("{}"))
	if !ok {
		t.Fatal("expected replayable response")
	}
	if !strings.HasPrefix(got, "HTTP 200\r\n") {
		t.Errorf("status line must be kept as captured, not invented:\n%s", got)
	}
	if strings.Contains(got, "Host:") {
		t.Errorf("responses must not gain a Host header:\n%s", got)
	}
}
