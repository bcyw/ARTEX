package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestTaskReportRendersConfirmedFindingsWithReplayableRaw checks the whole
// deliverable path: confirmed-only selection, report sections, and raw packets
// reconstructed from bound evidence snapshots.
func TestTaskReportRendersConfirmedFindingsWithReplayableRaw(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || finding.TaskID == nil {
		t.Fatal(err)
	}
	taskID := *finding.TaskID

	seedServerEvidenceFlow(t, s, "base", []byte("owner body"))
	seedServerEvidenceFlow(t, s, "proof", []byte(`{"order":"victim"}`))
	base := fmt.Sprintf("/api/exploration/findings/%d/traffic", f.FindingID)
	if w := req("POST", base, `{"traffic_refs":[{"traffic_id":"base","role":"baseline","note":"用受害者自己的账号读取"},{"traffic_id":"proof","role":"proof"}]}`); w.Code != 200 {
		t.Fatalf("bind: %d %s", w.Code, w.Body)
	}
	if _, err = s.m.pg.Exec(`INSERT INTO finding_report_sections(finding_id,description,impact,remediation,session)
VALUES($1,'订单接口只校验登录态，不校验归属。','1. 读取他人订单。','1. 按会话用户校验归属。','测试账号 A')`, f.FindingID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.SetFindingStatus(f.FindingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	pending, err := s.m.pg.GetTask(taskID)
	if err != nil || pending == nil {
		t.Fatal(err)
	}
	if _, err = s.evidenceStore().Record(t.Context(), db.RecordFindingInput{
		TaskID: taskID, ExplorationID: pending.ExplorationID, Summary: "未确认漏洞", Severity: "critical",
	}, nil); err != nil {
		t.Fatal(err)
	}

	w := req("GET", fmt.Sprintf("/api/report?task=%d", taskID), "")
	if w.Code != 200 {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	md := w.Body.String()

	for _, want := range []string{
		"# Evidence API",
		"## 漏洞等级\n\n低危",
		"## 漏洞类型\n\nTEST",
		"## 漏洞URL\n\nhttp://evidence.local/",
		"## 漏洞描述\n\n订单接口只校验登录态，不校验归属。",
		"## 测试账号与会话上下文\n\n测试账号 A",
		"### Step 1（对照）",
		"用受害者自己的账号读取",
		"```http\nPOST / HTTP/1.1\r\nHost: evidence.local\n```",
		"```http\nHTTP/1.1 200 OK\r\n",
		"owner body",
		"### Step 2（证明）",
		`{"order":"victim"}`,
		"结果：HTTP 200",
		"## 漏洞危害\n\n1. 读取他人订单。",
		"## 修复建议\n\n1. 按会话用户校验归属。",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q\n---\n%q", want, md)
		}
	}
	urlBlock := md[strings.Index(md, "## 漏洞URL"):]
	if end := strings.Index(urlBlock, "\n## "); end >= 0 {
		urlBlock = urlBlock[:end]
	}
	if strings.Count(urlBlock, "http://evidence.local/") != 1 {
		t.Errorf("duplicate URLs must collapse to one line\n---\n%s", urlBlock)
	}
	for _, unwanted := range []string{"未确认漏洞", "任务目标", "生成时间", "测试资产范围", "未绑定", "待补充"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("report must not contain %q\n---\n%s", unwanted, md)
		}
	}
}

// TestTaskReportFallsBackToSummaryWithoutAnnotation keeps legacy findings
// renderable: old rows have no deliverable sections, so summary stands in and
// nothing is annotated as missing.
func TestTaskReportFallsBackToSummaryWithoutAnnotation(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)
	finding, err := s.m.pg.GetFinding(f.FindingID)
	if err != nil || finding.TaskID == nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.SetFindingStatus(f.FindingID, db.FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err = s.m.pg.Exec(`UPDATE findings SET evidence=$2 WHERE id=$1`, f.FindingID, "curl -i http://evidence.local/"); err != nil {
		t.Fatal(err)
	}

	w := req("GET", fmt.Sprintf("/api/report?task=%d", *finding.TaskID), "")
	if w.Code != 200 {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	md := w.Body.String()
	if !strings.Contains(md, "## 漏洞描述\n\nbound evidence") {
		t.Errorf("legacy summary must fill the description:\n%s", md)
	}
	if !strings.Contains(md, "## 漏洞复现步骤（POC）\n\n```\ncurl -i http://evidence.local/") {
		t.Errorf("unbound finding must keep its PoC text:\n%s", md)
	}
	for _, unwanted := range []string{"待补充", "未绑定", "占位"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("report must not contain %q\n%s", unwanted, md)
		}
	}
}
