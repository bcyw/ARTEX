package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	// Paging by the pointer must restore the exact tail without re-requesting.
	got := toolText(t, tr, "traffic_blob", map[string]any{"hash": hash, "offset": len(big) - len(tail), "length": 64})
	if !strings.Contains(got, strings.TrimSpace(tail)) {
		t.Fatalf("traffic_blob 未取回预览之外的内容：\n%s", clip(got, 300))
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
	if !strings.Contains(page, "[response offset=5000") || !strings.Contains(page, "总长=") || !strings.Contains(page, "剩余=") {
		t.Fatalf("分页结果缺少偏移/总长元数据：\n%s", clip(page, 300))
	}

	// Page metadata must survive clipping independent of the body text.
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
	if info.Availability == "present" {
		t.Fatalf("缺失正文不应报告为 present：%+v", info)
	}
}

func TestTrafficGetPageValidation(t *testing.T) {
	tr, _ := openTraffic(t)
	body := bytes.Repeat([]byte("0123456789"), 1000)
	tr.record(newFlow("limits.example.com", "GET", "/limits", nil, body))
	id := onlyExchangeID(t, tr)

	first := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": 0, "length": 100000})
	if !strings.Contains(first, fmt.Sprintf("本次=%d", maxBlobRead)) {
		t.Fatalf("单页读取未被上限约束：\n%s", clip(first, 200))
	}
	// Offsets are original bytes: two adjacent 8KB pages reassemble the body.
	var joined []byte
	for offset := 0; offset < len(body); {
		page := toolText(t, tr, "traffic_get", map[string]any{"id": id, "side": "response", "offset": offset})
		start := strings.IndexByte(page, '\n')
		if start < 0 {
			t.Fatalf("分页结果缺少正文：%q", page)
		}
		joined = append(joined, page[start+1:]...)
		offset += maxBlobRead
	}
	if !bytes.Equal(joined, body) {
		t.Fatalf("逐页读取未能还原正文：got %d bytes", len(joined))
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
