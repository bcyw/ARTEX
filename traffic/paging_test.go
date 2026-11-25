package traffic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// toolText runs one traffic tool and returns its plain-text result.
func toolText(t *testing.T, tr *Traffic, name string, in map[string]any) string {
	t.Helper()
	for _, tool := range tr.Tools() {
		if tool.Name() != name {
			continue
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		res, err := tool.Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(name, err)
		}
		if res.IsError {
			t.Fatalf("%s returned error: %v", name, res)
		}
		var text strings.Builder
		for _, c := range res.Content {
			text.WriteString(c.Text)
		}
		return text.String()
	}
	t.Fatalf("tool %s not found", name)
	return ""
}

// trafficToolFails reports whether the tool surfaced an error result.
func trafficToolFails(t *testing.T, tr *Traffic, name string, in map[string]any) bool {
	t.Helper()
	for _, tool := range tr.Tools() {
		if tool.Name() != name {
			continue
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		res, err := tool.Call(context.Background(), raw, nil)
		return err != nil || res.IsError
	}
	t.Fatalf("tool %s not found", name)
	return false
}

// A body past the inline threshold loses its blob pointer today: traffic_get
// clips the assembled text, and the pointer sits after the preview. The worker
// then cannot tell that more content exists at all.
func TestTrafficGetKeepsBlobPointerAndPages(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("驱动未启用 FTS5")
	}
	const host = "dump.example.com"
	tail := "\nDB_PASSWORD=hunter2"
	big := []byte(strings.Repeat("-- MySQL dump\n", maxInlineBody/14+2000) + tail)
	tr.record(newFlow(host, "GET", "/backup.sql", nil, big, withRespType("application/sql")))
	id := onlyExchangeID(t, tr)

	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	out := toolText(t, tr, "traffic_get", map[string]any{"id": id})
	if !strings.Contains(out, "@blob sha256:"+hash) {
		t.Fatalf("traffic_get 丢失了 blob 指针，worker 无法继续取回：\n%s", clip(out, 600))
	}

	got := toolText(t, tr, "traffic_blob", map[string]any{"hash": hash, "offset": len(big) - len(tail), "length": 64})
	if !strings.Contains(got, strings.TrimSpace(tail)) {
		t.Fatalf("traffic_blob 未取回预览之外的内容：\n%s", clip(got, 300))
	}
}

// Binary blobs cannot be shown as text: every page must return base64 bytes whose
// reported length matches what was actually returned, so paging reassembles the
// original file instead of dropping the tail of each 8 KiB window.
func TestTrafficBlobPagesBinaryBytesLosslessly(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("驱动未启用 FTS5")
	}
	body := bytes.Repeat([]byte{0x00, 0xff, 0x10, 0x80, 0x7f}, maxInlineBody)
	tr.record(newFlow("blob-bytes.example.com", "GET", "/payload.bin", nil, body, withRespType("application/octet-stream")))
	id := onlyExchangeID(t, tr)
	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	var joined []byte
	for offset := 0; offset < len(body); {
		out := toolText(t, tr, "traffic_blob", map[string]any{"hash": hash, "offset": offset})
		var page struct {
			Encoding  string `json:"encoding"`
			Data      string `json:"data"`
			Offset    int64  `json:"offset"`
			Next      int64  `json:"next_offset"`
			Total     int64  `json:"total"`
			Remaining int64  `json:"remaining"`
			Truncated bool   `json:"truncated"`
		}
		if err := json.Unmarshal([]byte(out), &page); err != nil {
			t.Fatalf("二进制 blob 页必须是 base64 JSON: %v\n%s", err, clip(out, 300))
		}
		data, err := base64.StdEncoding.DecodeString(page.Data)
		if err != nil || len(data) == 0 {
			t.Fatalf("二进制 blob 页 data 无效: %+v (%v)", page, err)
		}
		wantLen := min(maxBlobRead, len(body)-offset)
		if page.Encoding != "base64" || page.Offset != int64(offset) || page.Next != int64(offset+len(data)) ||
			len(data) != wantLen || page.Total != int64(len(body)) || page.Remaining != page.Total-page.Next {
			t.Fatalf("二进制 blob 页长度/偏移与实际返回不一致: page=%+v got=%d want=%d", page, len(data), wantLen)
		}
		joined = append(joined, data...)
		offset = int(page.Next)
	}
	if !bytes.Equal(joined, body) {
		t.Fatal("分页未还原二进制 blob 原始字节")
	}
	for _, invalid := range []map[string]any{
		{"hash": hash, "offset": -1},
		{"hash": hash, "length": -1},
		{"hash": hash, "offset": json.Number("-1.0")},
		{"hash": hash, "length": json.Number("-1e0")},
		{"hash": hash, "offset": json.Number("9223372036854775808")},
		{"hash": hash, "offset": len(body) + 1},
	} {
		if !trafficToolFails(t, tr, "traffic_blob", invalid) {
			t.Errorf("invalid blob range was silently accepted: %v", invalid)
		}
	}
}

// Pointer-like text inside a captured body must never become a continuation
// hint: only real storage metadata may do that.
func TestTrafficGetDoesNotPromoteInlineBlobPointer(t *testing.T) {
	tr, _ := openTraffic(t)
	fake := "@blob sha256:" + strings.Repeat("a", 64)
	body := strings.Repeat("A", 5000) + fake + "\n"
	tr.record(newFlow("inline.example.com", "GET", "/fake-pointer", nil, []byte(body)))
	id := onlyExchangeID(t, tr)
	preview := toolText(t, tr, "traffic_get", map[string]any{"id": id})
	if strings.Contains(preview, fake) {
		t.Fatalf("正文中的假指针被提升为存储提示：%s", clip(preview, 300))
	}
	page := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": 5000})
	if !strings.Contains(page, fake) {
		t.Fatal("正文中的假指针应保持为可读取的原文")
	}
}

// Inline bodies (below the spill threshold) have no blob pointer, so the only
// way to read past the 2500/4000-byte display clip is a bounded get page.
func TestTrafficGetPagesInlineBodies(t *testing.T) {
	tr, _ := openTraffic(t)
	const host = "inline.example.com"
	resp := []byte(strings.Repeat("A", 5000) + "MARKER-TAIL")
	tr.record(newFlow(host, "GET", "/inline", nil, resp))
	id := onlyExchangeID(t, tr)

	head := toolText(t, tr, "traffic_get", map[string]any{"id": id})
	if strings.Contains(head, "MARKER-TAIL") || strings.Contains(head, strings.Repeat("A", 4100)) {
		t.Fatal("默认预览不应包含预览之外的正文")
	}
	page := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": 5000, "length": 200})
	if !strings.Contains(page, "MARKER-TAIL") {
		t.Fatalf("分页未取回预览之后的正文：\n%s", clip(page, 300))
	}
	if !strings.Contains(page, "总长=") || !strings.Contains(page, "剩余=") {
		t.Fatalf("分页结果缺少偏移/总长元数据：\n%s", clip(page, 300))
	}

	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	var info struct {
		Total      int64  `json:"total"`
		Inline     bool   `json:"inline"`
		BlobSHA256 string `json:"blob_sha256"`
	}
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatalf("meta_only 应返回 JSON：%v\n%s", err, clip(meta, 300))
	}
	if info.Total != int64(len(resp)) || !info.Inline || info.BlobSHA256 != "" {
		t.Fatalf("内联正文元数据不正确：%+v", info)
	}
}

func TestTrafficGetRejectsUndecodableRanges(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("ranges.example.com", "POST", "/range", []byte("request"), []byte("response")))
	id := onlyExchangeID(t, tr)
	for _, field := range []string{"offset", "length"} {
		for _, value := range []json.Number{"9223372036854775808", "-1.0", "-1e0"} {
			args := map[string]any{"id": id, "side": "response", field: value}
			if !trafficToolFails(t, tr, "traffic_get", args) {
				t.Errorf("invalid traffic range was silently accepted: %v", args)
			}
		}
	}
}

func TestTrafficGetMetaDistinguishesMissingAndEmptyBody(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("empty.example.com", "GET", "/empty", nil, nil))
	id := onlyExchangeID(t, tr)
	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	var info struct {
		Availability string `json:"availability"`
		Total        int64  `json:"total"`
	}
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "present" || info.Total != 0 {
		t.Fatalf("零长度正文应区分于缺失：%+v", info)
	}

	if _, err := tr.DB().Exec(`UPDATE exchange_bodies SET resp_body=NULL WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	meta = toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "missing" {
		t.Fatalf("缺失正文应标为 missing：%+v", info)
	}
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response"}) {
		t.Fatal("缺失正文不能读成空正文")
	}
}

// An omitted browser response body is unknown, and historical imports cannot
// prove an empty response was observed.
func TestTrafficGetBrowserBodyAvailability(t *testing.T) {
	tr, _ := openTraffic(t)
	id, err := tr.ImportBrowser(BrowserExchange{URL: "https://browser.example.com/", Method: "GET", Status: 200, ResponseBodyOmitted: true})
	if err != nil {
		t.Fatal(err)
	}
	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	var info struct {
		Availability string `json:"availability"`
		Warning      string `json:"warning"`
	}
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "missing" || !strings.Contains(info.Warning, "浏览器导入") {
		t.Fatalf("省略正文的错误可用性: %s", meta)
	}
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response"}) {
		t.Fatal("省略正文不应读取为空")
	}

	// Historical row: the flag did not exist yet and the old importer stored an
	// empty blob, so an empty body cannot prove the target returned nothing.
	id2, err := tr.ImportBrowser(BrowserExchange{URL: "https://browser.example.com/hist", Method: "GET", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`UPDATE exchange_bodies SET resp_omitted=NULL WHERE id=?`, id2); err != nil {
		t.Fatal(err)
	}
	meta = toolText(t, tr, "traffic_get", map[string]any{"id": id2, "side": "response", "meta_only": true})
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "unknown" || !strings.Contains(info.Warning, "浏览器导入") {
		t.Fatalf("历史空正文应标为 unknown 并保留警告: %s", meta)
	}

	// A real empty response recorded by the importer stays present: an observed
	// zero-length body must not be folded into the unknown historical state.
	id3, err := tr.ImportBrowser(BrowserExchange{URL: "https://browser.example.com/empty", Method: "GET", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	meta = toolText(t, tr, "traffic_get", map[string]any{"id": id3, "side": "response", "meta_only": true})
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "present" {
		t.Fatalf("真实空响应应保持 present: %s", meta)
	}
	page := toolText(t, tr, "traffic_get", map[string]any{"id": id3, "side": "response", "encoding": "base64"})
	var empty struct {
		Data     string `json:"data"`
		Total    int    `json:"total"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal([]byte(page), &empty); err != nil || empty.Data != "" || empty.Total != 0 || empty.Encoding != "base64" {
		t.Fatalf("真实空响应应可读取为零字节页: %s (%v)", page, err)
	}
}

// A body with a recorded length longer than its stored bytes was only partially
// captured, and a spilled body whose blob vanished is not fully readable.
func TestTrafficGetReportsPartialAndMissingBlob(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("驱动未启用 FTS5")
	}
	big := []byte(strings.Repeat("x", maxInlineBody+5000))
	tr.record(newFlow("partial.example.com", "GET", "/partial", nil, big))
	id := onlyExchangeID(t, tr)
	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tr.dir, "_blobs", "sha256", hash[:2], hash+".bin")); err != nil {
		t.Fatal(err)
	}
	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	var info struct {
		Availability string `json:"availability"`
		Warning      string `json:"warning"`
		Total        int64  `json:"total"`
	}
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err)
	}
	if info.Availability != "partial" || info.Total != int64(len(big)) || info.Warning == "" {
		t.Fatalf("缺失 blob 应标为 partial 并保留记录长度: %s", meta)
	}
	// The surviving preview is still readable; paging past it is not claimed.
	page := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": 0, "length": 100})
	if !strings.Contains(page, "xxxx") {
		t.Fatalf("部分捕获的内联预览应可读: %s", clip(page, 200))
	}
	// A missing spilled blob still leaves an inline preview, but paging beyond
	// that surviving prefix must terminate instead of advertising unread bytes.
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": maxInlineBody, "length": 100, "encoding": "base64"}) {
		t.Fatal("缺失 blob 的不可读尾部应明确报错，不能返回无进展分页")
	}
}

func TestTrafficGetMissingBinaryBlobDoesNotExposeTagAsBody(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("驱动未启用 FTS5")
	}
	body := bytes.Repeat([]byte{0x00, 0xff, 0x01, 0x80}, maxInlineBody)
	tr.record(newFlow("binary-missing.example.com", "GET", "/binary", nil, body, withRespType("application/octet-stream")))
	id := onlyExchangeID(t, tr)
	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tr.dir, "_blobs", "sha256", hash[:2], hash+".bin")); err != nil {
		t.Fatal(err)
	}
	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	if !strings.Contains(meta, `"availability":"partial"`) || !strings.Contains(meta, `"total":`) {
		t.Fatalf("缺失 blob 元数据不完整：%s", meta)
	}
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "encoding": "base64", "offset": 0}) {
		t.Fatal("binaryTag 不能作为遗失 binary 正文的原始字节返回")
	}
}

func TestTrafficGetReadsLegacyBodiesWithoutExchangeBodyRow(t *testing.T) {
	tr, dir := openTraffic(t)
	rel := "legacy/1700000000-0001"
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	request := []byte("POST /legacy HTTP/1.1\r\n\r\nbody")
	response := append([]byte("HTTP/1.1 200 OK\r\n\r\n"), bytes.Repeat([]byte("旧"), 3000)...)
	if err := os.WriteFile(filepath.Join(path, "request.http"), request, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "response.http"), response, 0o644); err != nil {
		t.Fatal(err)
	}
	const id = "legacy-readable"
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'legacy.example.com','POST','/legacy','http://legacy/legacy',200,'text/plain',?,?,?)`, id, len(request), len(response), rel); err != nil {
		t.Fatal(err)
	}
	var joined []byte
	for offset := 0; offset < len(response); {
		out := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": offset, "length": 8191, "encoding": "base64"})
		var page struct {
			Data  string `json:"data"`
			Next  int    `json:"next_offset"`
			Total int    `json:"total"`
		}
		if err := json.Unmarshal([]byte(out), &page); err != nil {
			t.Fatal(err, out)
		}
		data, err := base64.StdEncoding.DecodeString(page.Data)
		if err != nil || len(data) == 0 || page.Next != offset+len(data) || page.Total != len(response) {
			t.Fatalf("legacy page=%+v err=%v", page, err)
		}
		joined = append(joined, data...)
		offset = page.Next
	}
	if !bytes.Equal(joined, response) {
		t.Fatal("legacy response 分页未无损还原")
	}
}

func TestTrafficGetReadsLegacyFullHeadersWithoutChangingRawOffsets(t *testing.T) {
	tr, dir := openTraffic(t)
	const id, rel = "legacy-headers", "legacy/headers"
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		side, head, separator, body string
	}{
		{"request", "POST /legacy HTTP/1.1\r\nX-Long: " + strings.Repeat("h", 5000), "\r\n\r\n", "request body"},
		{"response", "HTTP 200\nContent-Type: text/plain", "\n\n", "response body\r\n\r\nnot headers"},
	}
	for _, fixture := range fixtures {
		if err := os.WriteFile(filepath.Join(path, fixture.side+".http"), []byte(fixture.head+fixture.separator+fixture.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'legacy.example.com','POST','/legacy','http://legacy/legacy',200,'text/plain',0,0,?)`, id, rel); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.side, func(t *testing.T) {
			full := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": fixture.side, "header_only": true})
			if strings.TrimRight(full, "\r\n") != fixture.head {
				t.Fatalf("legacy header_only did not return the complete stored head: %q", clip(full, 200))
			}
			offset := len(fixture.head) + len(fixture.separator)
			out := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": fixture.side, "offset": offset, "encoding": "base64"})
			var page struct {
				Data string `json:"data"`
				Next int    `json:"next_offset"`
			}
			if err := json.Unmarshal([]byte(out), &page); err != nil {
				t.Fatal(err, out)
			}
			body, err := base64.StdEncoding.DecodeString(page.Data)
			if err != nil || string(body) != fixture.body || page.Next != offset+len(fixture.body) {
				t.Fatalf("legacy raw byte offsets changed: page=%+v err=%v", page, err)
			}
		})
	}
}

func TestTrafficGetReportsMissingLegacyBodies(t *testing.T) {
	tr, dir := openTraffic(t)
	rel := "legacy/missing"
	if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
		t.Fatal(err)
	}
	const id = "legacy-missing"
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'legacy.example.com','GET','/missing','http://legacy/missing',200,'',10,20,?)`, id, rel); err != nil {
		t.Fatal(err)
	}
	meta := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "meta_only": true})
	var info struct {
		Availability string `json:"availability"`
		Warning      string `json:"warning"`
	}
	if err := json.Unmarshal([]byte(meta), &info); err != nil {
		t.Fatal(err, meta)
	}
	if info.Availability != "missing" || info.Warning == "" {
		t.Fatalf("legacy 缺失正文可用性错误: %s", meta)
	}
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response"}) {
		t.Fatal("缺失 legacy 正文不能读成空响应")
	}
}

// Long headers need their own complete read path: the default preview clips
// them, and body paging does not return them.
func TestTrafficGetReadsFullHeaders(t *testing.T) {
	tr, _ := openTraffic(t)
	longHead := "GET / HTTP/1.1\r\nX-Long: " + strings.Repeat("h", 5000) + "\r\n"
	tr.record(newFlow("headers.example.com", "GET", "/h", nil, []byte("ok")))
	id := onlyExchangeID(t, tr)
	if _, err := tr.DB().Exec(`UPDATE exchange_bodies SET req_head=? WHERE id=?`, longHead, id); err != nil {
		t.Fatal(err)
	}
	preview := toolText(t, tr, "traffic_get", map[string]any{"id": id})
	if strings.Count(preview, "h") > 2500 {
		t.Fatal("默认预览应裁剪超长头部")
	}
	full := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "request", "header_only": true})
	if !strings.Contains(full, strings.Repeat("h", 5000)) {
		t.Fatalf("header_only 未返回完整头部: %d bytes", len(full))
	}
}

// Without an encoding, a chunk that splits a multi-byte rune must not be
// replaced: it is returned as base64 so paging restores exact bytes.
func TestTrafficGetBase64RestoresStoredBytes(t *testing.T) {
	tr, _ := openTraffic(t)
	body := append(bytes.Repeat([]byte("中文🙂"), 1000), 0, 255)
	tr.record(newFlow("bytes.example.com", "POST", "/bytes", body, body))
	id := onlyExchangeID(t, tr)
	for _, side := range []string{"request", "response"} {
		var joined []byte
		for offset := 0; offset < len(body); {
			out := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": side, "offset": offset, "length": 8191})
			var page struct {
				Data       string `json:"data"`
				Encoding   string `json:"encoding"`
				NextOffset int    `json:"next_offset"`
				Total      int    `json:"total"`
			}
			if err := json.Unmarshal([]byte(out), &page); err != nil {
				t.Fatalf("跨页多字节正文应返回无损 JSON，而非替换字符: %v", err)
			}
			data, err := base64.StdEncoding.DecodeString(page.Data)
			if err != nil || page.Encoding != "base64" || page.NextOffset != offset+len(data) || len(data) == 0 || page.Total != len(body) {
				t.Fatalf("错误的字节页: %+v, %v", page, err)
			}
			joined = append(joined, data...)
			offset = page.NextOffset
		}
		if !bytes.Equal(joined, body) {
			t.Fatalf("%s 未还原原始字节", side)
		}
	}
	if !trafficToolFails(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "encoding": "unknown"}) {
		t.Fatal("未知编码应拒绝")
	}
}

func TestTrafficGetPageValidation(t *testing.T) {
	tr, _ := openTraffic(t)
	body := bytes.Repeat([]byte("0123456789"), 1000)
	tr.record(newFlow("limits.example.com", "GET", "/limits", nil, body))
	id := onlyExchangeID(t, tr)

	first := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": 0, "length": 100000})
	if !strings.Contains(first, "本次=8192") {
		t.Fatalf("单页读取未被上限约束：\n%s", clip(first, 200))
	}
	for name, in := range map[string]map[string]any{
		"负偏移":   {"id": id, "side": "response", "offset": -5},
		"未知正文侧": {"id": id, "side": "headers"},
	} {
		if !trafficToolFails(t, tr, "traffic_get", in) {
			t.Fatalf("%s 应返回错误", name)
		}
	}
}
