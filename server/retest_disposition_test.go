package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/db"
)

// Scripted verdicts exercise the real conversation/tool/HTTP lifecycle. They
// establish disposition and history semantics, not the accuracy of a retest.
func TestRetestInconclusivePreservesDispositionThroughHTTP(t *testing.T) {
	for _, initial := range []string{db.FindingPending, db.FindingInProgress} {
		t.Run(initial, func(t *testing.T) {
			s, fid := newRetestServer(t)
			w := retestRequest(s.patchFinding, http.MethodPatch, fid, `{"status":"`+initial+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("set initial status: %d %s", w.Code, w.Body)
			}
			checkFinding := func(want string) {
				t.Helper()
				w := retestRequest(s.getFinding, http.MethodGet, fid, "")
				var got struct {
					Status   string `json:"status"`
					Evidence string `json:"evidence"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Status != want || got.Evidence != "original proof" {
					t.Fatalf("finding API: %d %s, want %s and unchanged proof", w.Code, w.Body, want)
				}
			}
			type verdict struct{ value, reason, evidence string }
			verdicts := []verdict{
				{"inconclusive", "会话过期", "原身份无法重新认证，正常对照未执行"},
				{"inconclusive", "工具失败", "执行工具无法启动，未获得目标响应"},
				{"reproduced", "相同权限下复现原危害", "受控夹具的正常对照成立，原危害再次出现"},
				{"inconclusive", "环境已变化", "正常对照不可用，不能判断原危害是否存在"},
			}
			for i, v := range verdicts {
				if i == len(verdicts)-1 {
					// An explicit manual decision stays authoritative across uncertainty.
					w := retestRequest(s.patchFinding, http.MethodPatch, fid, `{"status":"false_positive"}`)
					if w.Code != http.StatusOK {
						t.Fatalf("manual review: %d %s", w.Code, w.Body)
					}
					initial = db.FindingFalsePositive
				}
				var calls atomic.Int32
				input, _ := json.Marshal(map[string]string{"verdict": v.value, "summary": v.reason, "evidence": v.evidence})
				setRetestProvider(s, retestProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
					if calls.Add(1) == 1 {
						return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "result", Name: "record_finding_retest_result", Input: input}}}, "tool_use", llm.Usage{}, nil
					}
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("结论已保存")}}, "end_turn", llm.Usage{}, nil
				}})
				w := retestRequest(s.startFindingRetest, http.MethodPost, fid, `{}`)
				if w.Code != http.StatusAccepted {
					t.Fatalf("start retest: %d %s", w.Code, w.Body)
				}
				waitRetestIdle(t, s)
				checkFinding(initial)
				w = retestRequest(s.listFindingRetests, http.MethodGet, fid, "")
				var history struct {
					Retests []db.FindingRetest `json:"retests"`
				}
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &history) != nil || len(history.Retests) != i+1 {
					t.Fatalf("history API: %d %s", w.Code, w.Body)
				}
				for j, r := range history.Retests {
					want := verdicts[i-j]
					if r.Verdict != want.value || r.Status != "completed" || r.Summary != want.reason || r.Evidence != want.evidence {
						t.Fatalf("history lost verdict/reason/evidence: %+v, want %+v", r, want)
					}
				}
			}
		})
	}
}
