package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bcyw/artex/agent"
	"github.com/bcyw/artex/db"
	"github.com/bcyw/artex/traffic"
)

func trafficEvidenceServer(t *testing.T) (*Server, *db.RecordedFinding, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	m.traffic, err = traffic.Open(filepath.Join(m.dir, "traffic"), ":0")
	if err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("traffic evidence API", "local evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, tid); m.pg.DeleteTask(tid) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newTestServer(t, ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()
	// The archive test below replaces the cancelled service context. Wait for
	// the side-question snapshot writer too before reusing this fixture.
	<-s.side.done
	token, err := signTestJWT(t, s)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	input := db.RecordFindingInput{TaskID: tid, ExplorationID: task.ExpID, Worker: "test", VulnClass: "TEST", Summary: "bound evidence", Name: "Evidence API", Severity: "low"}
	f, err := s.evidenceStore().Record(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, request
}

func seedServerEvidenceFlow(t *testing.T, s *Server, id string, body []byte) {
	t.Helper()
	seedServerEvidenceBodies(t, s, id, []byte{}, body)
}

func seedServerEvidenceBodies(t *testing.T, s *Server, id string, request, response []byte) {
	t.Helper()
	_, err := s.m.traffic.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path) VALUES(?,1,'evidence.local','POST','/','http://evidence.local/',200,'application/octet-stream',?,?,'')`, id, len(request), len(response))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.m.traffic.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,resp_head,req_body,resp_body) VALUES(?,'POST / HTTP/1.1','HTTP/1.1 200 OK',?,?)`, id, request, response)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindingTrafficBodyBase64RestoresBothSides(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	reqBody := []byte("abc中\x00\xff")
	respBody := []byte("xyz🙂\x00\x80end")
	seedServerEvidenceBodies(t, s, "both-sides", reqBody, respBody)
	list, err := s.evidenceStore().Bind(t.Context(), f.FindingID, []db.TrafficRef{{TrafficID: "both-sides"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/exploration/findings/%d/traffic/%d/body?encoding=base64", f.FindingID, list.Bindings[0].ID)
	for _, tc := range []struct {
		side string
		body []byte
		hash string
	}{
		{"request", reqBody, list.Bindings[0].Snapshot.ReqHash},
		{"response", respBody, list.Bindings[0].Snapshot.RespHash},
	} {
		t.Run(tc.side, func(t *testing.T) {
			const length = 4 // The first page ends inside a UTF-8 character on each side.
			wantHash := fmt.Sprintf("%x", sha256.Sum256(tc.body))
			var joined []byte
			for offset := 0; offset < len(tc.body); {
				w := request("GET", fmt.Sprintf("%s&side=%s&offset=%d&length=%d", path, tc.side, offset, length), "")
				if w.Code != 200 {
					t.Fatal(w.Code, w.Body)
				}
				var page struct {
					Encoding   string `json:"encoding"`
					Content    []byte `json:"content"` // JSON decodes standard base64 strings into []byte.
					SHA256     string `json:"sha256"`
					Total      int    `json:"total"`
					Offset     int    `json:"offset"`
					NextOffset int    `json:"next_offset"`
					Truncated  *bool  `json:"truncated"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
					t.Fatal(err, w.Body)
				}
				end := min(offset+length, len(tc.body))
				if page.Encoding != "base64" || page.SHA256 != tc.hash || page.SHA256 != wantHash || page.Total != len(tc.body) ||
					page.Offset != offset || page.NextOffset != end || page.Truncated == nil || *page.Truncated != (end < len(tc.body)) {
					t.Fatalf("unexpected page: %s", w.Body)
				}
				joined = append(joined, page.Content...)
				offset = page.NextOffset
			}
			if !bytes.Equal(joined, tc.body) {
				t.Fatalf("joined bytes = %x; want %x", joined, tc.body)
			}
		})
	}
}

func TestFindingTrafficBodyBase64EdgesAndLegacyPreview(t *testing.T) {
	s, f, request := trafficEvidenceServer(t)
	seedServerEvidenceBodies(t, s, "edges", []byte("req"), []byte{})
	list, err := s.evidenceStore().Bind(t.Context(), f.FindingID, []db.TrafficRef{{TrafficID: "edges"}})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/exploration/findings/%d/traffic/%d/body", f.FindingID, list.Bindings[0].ID)

	w := request("GET", path+"?encoding=base64&side=response", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var page struct {
		Content   []byte `json:"content"`
		Total     int    `json:"total"`
		Next      int64  `json:"next_offset"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err, w.Body)
	}
	if len(page.Content) != 0 || page.Total != 0 || page.Next != 0 || page.Truncated {
		t.Fatalf("empty body page = %s", w.Body)
	}

	if w = request("GET", path+"?encoding=hex", ""); w.Code != 400 {
		t.Fatal("unknown encoding must be rejected", w.Code, w.Body)
	}
	if w = request("GET", path+"?encoding=base64&offset=-1", ""); w.Code == 200 {
		t.Fatal("negative offset must fail", w.Body)
	}
	if w = request("GET", path+"?encoding=base64&offset=99&side=response", ""); w.Code == 200 {
		t.Fatal("offset past end must fail", w.Body)
	}

	w = request("GET", path+"?side=response", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var preview evidencePreview
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
		t.Fatal(err, w.Body)
	}
	if preview.Total != 0 || preview.Content != "" || preview.Truncated {
		t.Fatalf("legacy preview changed for empty body: %s", w.Body)
	}
}

func TestTrafficGetSchemaUpgradePreservesBindingAndCustomization(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	old, err := pg.GetTool("traffic_get")
	if err != nil || old == nil {
		t.Fatal("missing traffic_get", err)
	}
	t.Cleanup(func() {
		bindings, _ := json.Marshal(old.Agents)
		_ = pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		_ = pg.SetSetting("traffic_get_paging_v2", "false")
	})

	// An old DB: legacy description + schema without the paging params.
	if err := pg.UpdateTool("traffic_get", trafficGetLegacyDescription, json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`), json.RawMessage(`["worker","reporter"]`), false); err != nil {
		t.Fatal(err)
	}
	_ = pg.SetSetting("traffic_get_paging_v2", "false")
	s.refreshTrafficGetSchema()
	tool, err := pg.GetTool("traffic_get")
	if err != nil || tool == nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(tool.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"side", "offset", "length", "meta_only"} {
		if len(schema.Properties[p]) == 0 {
			t.Fatalf("升级后缺少参数 %s: %s", p, tool.Schema)
		}
	}
	if tool.Description == trafficGetLegacyDescription || !strings.Contains(tool.Description, "分页") {
		t.Fatalf("内置描述未升级: %q", tool.Description)
	}
	if tool.Enabled || len(tool.Agents) != 2 {
		t.Fatalf("升级改动了用户绑定/启用状态: %+v", tool)
	}

	// A user-edited description and hand-tuned schema survive the upgrade: only
	// absent properties are added, never existing constraints or required lists.
	customSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","pattern":"^fixture-","description":"custom ID"},"length":{"type":"integer","maximum":128},"custom":{"type":"boolean"}},"required":["id","custom"]}`)
	if err := pg.UpdateTool("traffic_get", "我的自定义说明", customSchema, json.RawMessage(`["worker"]`), true); err != nil {
		t.Fatal(err)
	}
	_ = pg.SetSetting("traffic_get_paging_v2", "false")
	s.refreshTrafficGetSchema()
	tool, _ = pg.GetTool("traffic_get")
	if tool.Description != "我的自定义说明" || !tool.Enabled || len(tool.Agents) != 1 {
		t.Fatalf("自定义配置被覆盖: %+v", tool)
	}
	var custom struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	if err := json.Unmarshal(tool.Schema, &custom); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"side", "offset", "meta_only", "encoding", "header_only"} {
		if len(custom.Properties[key]) == 0 {
			t.Fatalf("升级后缺少参数 %s: %s", key, tool.Schema)
		}
	}
	if !strings.Contains(string(custom.Properties["id"]), "^fixture-") || !strings.Contains(string(custom.Properties["length"]), "128") ||
		len(custom.Properties["custom"]) == 0 || strings.Join(custom.Required, ",") != "id,custom" || custom.AdditionalProperties {
		t.Fatalf("自定义 schema 被覆盖: %s", tool.Schema)
	}

	// The v2 flag also upgrades a database that already ran the old v1 migration.
	_ = pg.SetSetting("traffic_get_paging_v1", "true")
	_ = pg.SetSetting("traffic_get_paging_v2", "false")
	if err := pg.UpdateTool("traffic_get", "我的自定义说明", customSchema, json.RawMessage(`["worker"]`), true); err != nil {
		t.Fatal(err)
	}
	s.refreshTrafficGetSchema()
	again, _ := pg.GetTool("traffic_get")
	if !strings.Contains(string(again.Schema), `"encoding"`) || again.Description != "我的自定义说明" {
		t.Fatalf("v1 已执行过的库未获得新参数: %s", again.Schema)
	}
}

// Binary blob paging changed shape: the worker must be told that binary pages come
// back as base64 JSON, while a user-edited traffic_blob description survives.
func TestTrafficBlobDescriptionUpgrade(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	old, err := pg.GetTool("traffic_blob")
	if err != nil || old == nil {
		t.Fatal("missing traffic_blob", err)
	}
	t.Cleanup(func() {
		bindings, _ := json.Marshal(old.Agents)
		_ = pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		_ = pg.SetSetting("traffic_blob_base64_v1", "false")
	})

	if err := pg.UpdateTool("traffic_blob", trafficBlobLegacyDescription, old.Schema, json.RawMessage(`["worker"]`), false); err != nil {
		t.Fatal(err)
	}
	_ = pg.SetSetting("traffic_blob_base64_v1", "false")
	s.refreshTrafficBlobDescription()
	upgraded, _ := pg.GetTool("traffic_blob")
	if upgraded.Description == trafficBlobLegacyDescription || !strings.Contains(upgraded.Description, "base64") {
		t.Fatalf("内置描述未升级: %q", upgraded.Description)
	}
	if upgraded.Enabled || len(upgraded.Agents) != 1 || upgraded.Agents[0] != "worker" {
		t.Fatalf("升级改动了用户绑定/启用状态: %+v", upgraded)
	}

	if err := pg.UpdateTool("traffic_blob", "我的 binary 读取说明", old.Schema, json.RawMessage(`["worker"]`), true); err != nil {
		t.Fatal(err)
	}
	_ = pg.SetSetting("traffic_blob_base64_v1", "false")
	s.refreshTrafficBlobDescription()
	custom, _ := pg.GetTool("traffic_blob")
	if custom.Description != "我的 binary 读取说明" || !custom.Enabled {
		t.Fatalf("自定义描述被覆盖: %+v", custom)
	}
}

func TestFindingTrafficToolUpgradePreservesCustomization(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatal("missing worker", err)
	}
	oldPrompt, _ := pg.CurrentPrompt(worker.ID)
	t.Cleanup(func() { pg.SavePrompt(worker.ID, oldPrompt, "restore test fixture", "test") })
	if _, err := pg.SavePrompt(worker.ID, "USER CUSTOM PROMPT", "test", "test"); err != nil {
		t.Fatal(err)
	}
	custom := json.RawMessage(`{"type":"object","properties":{"evidence":{"type":"string","description":"user evidence instructions"}},"required":["evidence"]}`)
	for _, key := range []string{"report_finding", "update_finding_report", "get_finding_traffic"} {
		old, err := pg.GetTool(key)
		if err != nil || old == nil {
			t.Fatal("missing tool", key, err)
		}
		t.Cleanup(func() {
			bindings, _ := json.Marshal(old.Agents)
			pg.UpdateTool(old.Key, old.Description, old.Schema, bindings, old.Enabled)
		})
		if err := pg.UpdateTool(key, "user description", custom, json.RawMessage(`["worker"]`), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := pg.SetSetting("finding_traffic_tools_v1", "false"); err != nil {
		t.Fatal(err)
	}
	s.seedFindingTrafficTools()
	for key, property := range map[string]string{"report_finding": "traffic_refs", "update_finding_report": "evidence_version"} {
		tool, err := pg.GetTool(key)
		if err != nil || tool == nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		}
		if err := json.Unmarshal(tool.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if tool.Enabled || tool.Description != "user description" || len(tool.Agents) != 1 || tool.Agents[0] != "worker" || len(schema.Required) != 1 || schema.Required[0] != "evidence" || len(schema.Properties[property]) == 0 || !strings.Contains(string(schema.Properties["evidence"]), "user evidence instructions") {
			t.Fatalf("custom configuration overwritten: %+v", tool)
		}
	}
	reader, _ := pg.GetTool("get_finding_traffic")
	if reader.Enabled || !contains(reader.Agents, "reporter") {
		t.Fatal("reader should be bound without enabling it")
	}
	if err := pg.RemoveAgentFromTool("reporter", "get_finding_traffic"); err != nil {
		t.Fatal(err)
	}
	s.seedFindingTrafficTools()
	reader, _ = pg.GetTool("get_finding_traffic")
	if contains(reader.Agents, "reporter") {
		t.Fatal("restart overwrote user's unbinding")
	}
	if got, _ := pg.CurrentPrompt(worker.ID); got != "USER CUSTOM PROMPT" {
		t.Fatal("custom prompt replaced")
	}
}

func TestFindingTrafficAPIAndExport(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	body := bytes.Repeat([]byte{0, 255, 65, 66}, 5000)
	for _, id := range []string{"a", "b", "c"} {
		seedServerEvidenceFlow(t, s, id, body)
	}
	base := fmt.Sprintf("/api/exploration/findings/%d/traffic", f.FindingID)
	w := req("POST", base, `{"traffic_refs":[{"traffic_id":"a","role":"baseline"},{"traffic_id":"b","role":"proof","note":"proof note"},{"traffic_id":"c"}]}`)
	if w.Code != 200 {
		t.Fatalf("bind: %d %s", w.Code, w.Body)
	}
	var list db.FindingTraffic
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Bindings) != 3 || list.Bindings[0].Snapshot.ReqHead != "" {
		t.Fatal("not a bounded summary")
	}
	first, second, third := list.Bindings[0].ID, list.Bindings[1].ID, list.Bindings[2].ID
	if w = req("PATCH", fmt.Sprintf("%s/%d", base, first), `{"version":0,"note":"stale"}`); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("PUT", base+"/order", fmt.Sprintf(`{"version":1,"binding_ids":["%d","%d","%d"]}`, third, first, second)); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("PUT", base+"/order", fmt.Sprintf(`{"version":2,"binding_ids":["%d"]}`, first)); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("GET", fmt.Sprintf("%s/%d", base, first), ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"binary":true`) {
		t.Fatal(w.Code, w.Body)
	}
	if w = req("GET", fmt.Sprintf("%s/%d/body?side=response&offset=20001", base, first), ""); w.Code != 422 {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	if w = req("GET", fmt.Sprintf("%s/%d/body?side=response&download=1", base, first), ""); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatal("download after original removal failed")
	}
	// IDs belong to the requested finding; cross-finding detail cannot be read.
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.GetTask(*finding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.evidenceStore().Record(t.Context(), db.RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "other", Severity: "low"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w = req("GET", fmt.Sprintf("/api/exploration/findings/%d/traffic/%d", other.FindingID, first), ""); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	exportURL := fmt.Sprintf("/api/exploration/findings/export?format=md-zip&scope=selected&ids=%d", f.FindingID)
	w = req("GET", exportURL, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	archive, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	binaries := 0
	linked := false
	for _, entry := range archive.File {
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(entry.Name, "/response.bin") {
			binaries++
			if !bytes.Equal(raw, body) {
				t.Fatal("export changed binary")
			}
		}
		if strings.HasSuffix(entry.Name, ".md") && bytes.Contains(raw, []byte(fmt.Sprintf("evidence/%d/%d/", f.FindingID, third))) {
			linked = true
		}
	}
	if binaries != 3 || !linked {
		t.Fatalf("missing attachments/links: %d %v", binaries, linked)
	}
	// Reports can use snapshots with capture stopped and original rows gone.
	result, err := s.toolGetFindingTraffic().Call(context.Background(), json.RawMessage(fmt.Sprintf(`{"finding_id":"%d"}`, f.FindingID)), nil)
	if err != nil || !strings.Contains(result.Flatten(), "proof note") {
		t.Fatal(result, err)
	}
	// Corrupt body must fail before an attachment response is sent.
	snap := list.Bindings[0].Snapshot
	path := filepath.Join(s.m.dir, "evidence", "blobs", snap.RespHash[:2], snap.RespHash+".bin")
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if w = req("GET", exportURL, ""); w.Code < 400 || strings.Contains(w.Header().Get("Content-Type"), "zip") {
		t.Fatal("corrupt export returned an attachment", w.Code)
	}
}

func TestFindingTrafficArchiveV3RoundTripAndRetry(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	ctx := context.Background()
	s.ctx = ctx
	body := []byte("evidence without original traffic\x00\xff")
	seedServerEvidenceFlow(t, s, "original", body)
	list, err := s.evidenceStore().Bind(ctx, f.FindingID, []db.TrafficRef{{TrafficID: "original", Role: "proof", Note: "keep note"}})
	if err != nil {
		t.Fatal(err)
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	tid := *finding.TaskID
	sharedTask, err := s.m.CreateTask("shared evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := strconv.ParseInt(sharedTask.ID, 10, 64)
	defer s.m.pg.DeleteTask(sid)
	shared, err := s.evidenceStore().Record(ctx, db.RecordFindingInput{TaskID: sid, ExplorationID: sharedTask.ExpID, Summary: "shared", Severity: "low"}, []db.TrafficRef{{TrafficID: "original"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	if err = s.m.SetTaskPaused(strconv.FormatInt(tid, 10), true); err != nil {
		t.Fatal(err)
	}
	job, err := s.m.pg.QueueTaskArchive(tid)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.EditFindingTraffic(ctx, f.FindingID, list.Bindings[0].ID, 1, nil, nil, true, nil); err == nil {
		t.Fatal("write allowed after archive queued")
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.m.pg.GetFinding(f.FindingID); got != nil {
		t.Fatal("archive retained hot finding")
	}
	if err = s.evidenceStore().Collect(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.evidenceStore().WithBinding(ctx, shared.FindingID, shared.Traffic.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
		r, _, err := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if r != nil {
			r.Close()
		}
		return err
	}); err != nil {
		t.Fatal("shared body deleted", err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	// Force a database error after validated body installation; then retry normally.
	if _, err = s.m.pg.Exec(`CREATE TRIGGER fail_evidence_restore_test BEFORE INSERT ON finding_traffic_bindings BEGIN SELECT RAISE(ABORT,'restore fixture failure'); END`); err != nil {
		t.Fatal(err)
	}
	defer s.m.pg.Exec(`DROP TRIGGER IF EXISTS fail_evidence_restore_test`)
	if err = s.runOneTaskArchiveJob(); err == nil {
		t.Fatal("expected restore failure")
	}
	if got, _ := s.m.pg.GetFinding(f.FindingID); got != nil {
		t.Fatal("partial restore")
	}
	if _, err = s.m.pg.Exec(`DROP TRIGGER fail_evidence_restore_test`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.QueueTaskArchiveRestore(job.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.runOneTaskArchiveJob(); err != nil {
		t.Fatal(err)
	}
	restored, err := s.m.pg.GetFindingTraffic(ctx, f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	b := restored.Bindings[0]
	if restored.Version != list.Version || b.ID != list.Bindings[0].ID || b.Note != "keep note" || b.Role != "proof" || b.Position != 0 {
		t.Fatalf("restored: %+v", restored)
	}
	if err = s.evidenceStore().WithBinding(ctx, f.FindingID, b.ID, func(b db.FindingTrafficBinding) error {
		r, _, err := s.evidenceStore().OpenBody(b.Snapshot, "response")
		if err != nil {
			return err
		}
		defer r.Close()
		got, err := io.ReadAll(r)
		if !bytes.Equal(got, body) {
			t.Fatal("restore changed body")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The read tool enforces task visibility too.
	result, err := s.toolGetFindingTraffic().Call(agent.WithRunInfo(ctx, agent.RunInfo{TaskID: sid}), json.RawMessage(fmt.Sprintf(`{"finding_id":"%d"}`, f.FindingID)), nil)
	if err != nil || !strings.Contains(result.Flatten(), "不可读取") {
		t.Fatal(result, err)
	}
}

func TestFindingTrafficFailedReportDoesNotTrigger(t *testing.T) {
	s, f, _ := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := s.m.pg.GetTask(*finding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var last int64
	if err = s.m.pg.QueryRow(`SELECT COALESCE(max(id),0) FROM activity`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if err = s.m.pg.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(last, 10)); err != nil {
		t.Fatal(err)
	}
	id, err := s.m.pg.Exploration(task.ExplorationID).AppendActivity(db.Activity{Kind: "tool_result", Tool: "report_finding", ToolUseID: "failure-fixture", IsError: true, Detail: "body missing"})
	if err != nil {
		t.Fatal(err)
	}
	// A nil server makes any attempted trigger fail this test immediately.
	scheduler := &Scheduler{pg: s.m.pg}
	scheduler.fireToolCalls([]*db.AgentTrigger{{OnToolCall: true, ToolNames: []string{"report_finding"}, AgentKey: "reporter"}})
	if got := scheduler.mustState(schedKeyLastToolCall); got != strconv.FormatInt(id, 10) {
		t.Fatal("failed finding must still advance watermark", got)
	}
}

func TestFindingTrafficUTF8SegmentsAndInheritedWrites(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	ctx := context.Background()
	text := strings.Repeat("中文证据🙂", 2000)
	seedServerEvidenceFlow(t, s, "unicode", []byte(text))
	list, err := s.evidenceStore().Bind(ctx, f.FindingID, []db.TrafficRef{{TrafficID: "unicode"}})
	if err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	offset := int64(0)
	for {
		var preview evidencePreview
		err = s.evidenceStore().WithBinding(ctx, f.FindingID, list.Bindings[0].ID, func(b db.FindingTrafficBinding) error {
			var e error
			preview, e = readEvidencePreview(s.evidenceStore(), b.Snapshot, "response", offset, 8192)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		if preview.Binary {
			t.Fatal("valid UTF-8 classified binary")
		}
		joined.WriteString(preview.Content)
		if !preview.Truncated {
			break
		}
		if preview.NextOffset <= offset {
			t.Fatal("preview made no progress")
		}
		offset = preview.NextOffset
	}
	if joined.String() != text {
		t.Fatal("UTF-8 character split damaged preview")
	}
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := s.m.CreateTaskWithOptions("inherited evidence API", "fixture", db.TaskCreateOptions{SourceTaskIDs: []int64{*finding.TaskID}})
	if err != nil {
		t.Fatal(err)
	}
	cid, _ := strconv.ParseInt(child.ID, 10, 64)
	defer s.m.pg.DeleteTask(cid)
	base := fmt.Sprintf("/api/exploration/findings/%d/traffic", f.FindingID)
	suffix := "?context_task=" + child.ID
	if w := req("GET", base+suffix, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, method := range []string{"POST", "PATCH", "PUT", "DELETE"} {
		path := base
		if method == "PATCH" || method == "DELETE" {
			path += fmt.Sprintf("/%d", list.Bindings[0].ID)
		}
		if method == "PUT" {
			path += "/order"
		}
		w := req(method, path+suffix, `{"version":1,"traffic_refs":[{"traffic_id":"unicode"}]}`)
		if w.Code != 403 {
			t.Fatal(method, w.Code, w.Body)
		}
	}
	if _, err = s.m.traffic.DeleteHost("evidence.local"); err != nil {
		t.Fatal(err)
	}
	result, err := s.toolUpdateFindingReport().Call(ctx, json.RawMessage(fmt.Sprintf(`{"finding_id":%d,"evidence_version":1,"report":%q}`, f.NodeID, compliantFindingReport+fmt.Sprintf("\n\n证据 #%d：已验证完整请求响应。", list.Bindings[0].ID))), nil)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	updated, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ReportEvidenceVersion != 1 || updated.EvidenceVersion != 1 {
		t.Fatal("report did not record the read evidence version")
	}
	for _, format := range []string{"md-single", "json", "csv"} {
		w := req("GET", fmt.Sprintf("/api/exploration/findings/export?scope=selected&ids=%d&format=%s", f.FindingID, format), "")
		if w.Code != 200 {
			t.Fatal(format, w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), fmt.Sprint(list.Bindings[0].ID)) {
			t.Fatal("export omitted evidence ID", format)
		}
	}
}
