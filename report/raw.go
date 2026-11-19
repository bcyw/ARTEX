package report

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxReportBody caps the body copied into a Markdown report. A body above the
// cap is dropped rather than truncated: a replayed packet must be byte-faithful.
const MaxReportBody = 1 << 20

// NormalizeRequest turns a captured request head+body into a packet that can be
// pasted into Burp Repeater or Yakit and sent as-is. It returns ok=false when
// the packet cannot be represented as faithful text (binary body, unknown
// Content-Encoding, oversized body); callers must then omit the block entirely
// instead of writing a placeholder.
func NormalizeRequest(head string, body []byte, fallbackURL string) (string, bool) {
	return normalize(head, body, fallbackURL, true)
}

// NormalizeResponse does the same for a response. The status line is kept as
// captured; the report never invents an HTTP version or reason phrase.
func NormalizeResponse(head string, body []byte) (string, bool) {
	return normalize(head, body, "", false)
}

func normalize(head string, body []byte, fallbackURL string, request bool) (string, bool) {
	if len(body) > MaxReportBody {
		return "", false
	}
	head = strings.ReplaceAll(head, "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(head, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return "", false
	}
	headers := lines[1:]

	decoded, gunzipped, ok := decodeBody(body, headers)
	if !ok {
		return "", false
	}

	out := make([]string, 0, len(headers)+2)
	start := strings.TrimSpace(lines[0])
	if request && !strings.Contains(start, " HTTP/") {
		start += " HTTP/1.1"
	}
	out = append(out, start)

	hasHost := false
	for _, line := range headers {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch strings.ToLower(headerName(line)) {
		case "content-length", "transfer-encoding":
			continue
		case "content-encoding":
			if gunzipped {
				continue
			}
		case "host":
			hasHost = true
		}
		out = append(out, line)
	}

	if request && !hasHost {
		if host := hostOf(fallbackURL); host != "" {
			out = append(out[:1], append([]string{"Host: " + host}, out[1:]...)...)
		}
	}
	if len(decoded) > 0 {
		out = append(out, "Content-Length: "+strconv.Itoa(len(decoded)))
	}

	raw := strings.Join(out, "\r\n") + "\r\n\r\n"
	if len(decoded) > 0 {
		raw += string(decoded)
	}
	return raw, true
}

func decodeBody(body []byte, headers []string) ([]byte, bool, bool) {
	encoding := strings.ToLower(strings.TrimSpace(headerValue(headers, "Content-Encoding")))
	if len(body) == 0 {
		// An empty body carries no encoding problem; dropping the header is safe.
		return nil, encoding != "" && encoding != "identity", true
	}
	switch {
	case strings.Contains(encoding, "gzip"):
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, false
		}
		defer zr.Close()
		decoded, err := io.ReadAll(io.LimitReader(zr, MaxReportBody+1))
		if err != nil || len(decoded) > MaxReportBody || !isText(decoded) {
			return nil, false, false
		}
		return decoded, true, true
	case encoding != "" && encoding != "identity":
		// br/deflate/zstd: the packet cannot be replayed verbatim after decode,
		// and shipping compressed bytes as text is garbage.
		return nil, false, false
	}
	if !isText(body) {
		return nil, false, false
	}
	return body, false, true
}

func isText(b []byte) bool {
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	control := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			control++
		}
	}
	return control*20 <= len(b)
}

func headerName(line string) string {
	if i := strings.IndexByte(line, ':'); i > 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func headerValue(headers []string, name string) string {
	for _, line := range headers {
		if strings.EqualFold(headerName(line), name) {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return u.Host
}
