package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
)

// taskReportInput assembles the deliverable report for one task. Everything the
// renderer needs is resolved here: confirmed findings, their report sections,
// asset labels and the bound evidence bodies. Nothing is guessed — a finding
// without bindings simply has no reproduction steps.
func (s *Server) taskReportInput(ctx context.Context, taskID int64) (report.Input, error) {
	rows, err := s.m.pg.ListTaskReportFindings(ctx, taskID)
	if err != nil {
		return report.Input{}, err
	}
	store := s.evidenceStore()
	in := report.Input{Findings: make([]report.Finding, 0, len(rows))}
	for _, row := range rows {
		f := report.Finding{
			Name:        row.Name,
			VulnClass:   row.VulnClass,
			Severity:    row.Severity,
			Description: row.Sections.Description,
			Summary:     row.Summary,
			Session:     row.Sections.Session,
			Impact:      row.Sections.Impact,
			Remediation: row.Sections.Remediation,
			PoC:         row.Evidence,
		}
		for _, b := range row.TrafficBindings {
			f.Steps = append(f.Steps, reportStep(store, b))
		}
		f.Assets = reportAssets(s.m.Assets(), row.AssetIDs, f.Steps)
		in.Findings = append(in.Findings, f)
	}
	return in, nil
}

// reportStep renders one binding as a reproduction step. request/response heads
// and bodies come from the immutable snapshot, which survives traffic deletion
// and task archiving.
func reportStep(store *evidence.Store, b db.FindingTrafficBinding) report.Step {
	step := report.Step{Role: b.Role, Note: b.Note, Method: b.Snapshot.Method, URL: b.Snapshot.URL, Status: b.Snapshot.Status}
	if reqBody, ok := evidenceBody(store, b.Snapshot, "request"); ok {
		if raw, ok := report.NormalizeRequest(b.Snapshot.ReqHead, reqBody, b.Snapshot.URL); ok {
			step.Request = raw
		}
	}
	if respBody, ok := evidenceBody(store, b.Snapshot, "response"); ok {
		if raw, ok := report.NormalizeResponse(b.Snapshot.RespHead, respBody); ok {
			step.Response = raw
		}
	}
	return step
}

// evidenceBody reads one side of a snapshot. ok=false means the blob is missing
// or corrupt, so the packet is omitted rather than rendered from partial data.
func evidenceBody(store *evidence.Store, snap db.TrafficEvidenceSnapshot, side string) ([]byte, bool) {
	f, _, err := store.OpenBody(snap, side)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, report.MaxReportBody+1))
	if err != nil {
		return nil, false
	}
	return body, true
}

// reportAssets lists affected assets, then adds hosts only seen in the bound
// packets. Asset rows are authoritative; packets cover findings recorded
// without asset ids.
func reportAssets(store *db.AssetStore, ids []int64, steps []report.Step) []string {
	var out []string
	seen := map[string]bool{}
	add := func(label string) {
		label = strings.TrimSpace(label)
		if label == "" || seen[strings.ToLower(label)] {
			return
		}
		seen[strings.ToLower(label)] = true
		out = append(out, label)
	}
	if len(ids) > 0 {
		if assets, err := store.GetByIDs(ids); err == nil {
			byID := make(map[int64]*db.Asset, len(assets))
			for _, a := range assets {
				byID[a.ID] = a
			}
			for _, id := range ids {
				if a := byID[id]; a != nil {
					add(reportAssetLabel(a))
				}
			}
		}
	}
	for _, step := range steps {
		add(report.HostOf(step.URL))
	}
	return out
}

// reportAssetLabel prefers the host over a full URL: the section names what is
// affected, not which endpoint was called.
func reportAssetLabel(a *db.Asset) string {
	switch {
	case a.Domain != "":
		return hostPort(a.Domain, a.Port)
	case a.IP != "":
		return hostPort(a.IP, a.Port)
	case a.URL != "":
		return report.HostOf(a.URL)
	case a.AppName != "":
		return a.AppName
	case a.BundleID != "":
		return a.BundleID
	}
	return ""
}

func hostPort(host string, port *int) string {
	if port != nil && *port > 0 {
		return fmt.Sprintf("%s:%d", host, *port)
	}
	return host
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		// 任务 ID 一律是数字；解析失败说明 ResolveTask 命中了非任务别名，宁可
		// 明确报错也不渲染一份空报告让人误以为任务没有发现。
		writeErr(w, 404, "task not found")
		return
	}
	in, err := s.taskReportInput(r.Context(), taskID)
	if err != nil {
		writeErr(w, 500, "读取报告数据失败")
		return
	}
	md := report.Markdown(in)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write([]byte(md))
}
