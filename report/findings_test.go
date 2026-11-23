package report

import (
	"strings"
	"testing"
	"time"

	"github.com/bcyw/artex/db"
)

// 导出物是交付物(ADR 0003):不含过程元数据,绑定角色只用中文名。
func TestExportOmitsProcessMetadata(t *testing.T) {
	f := &db.DBFinding{
		ID: 3, Name: "示例漏洞", Severity: "high", Status: "confirmed",
		Report:          "## 漏洞名称\n…",
		Evidence:        "GET /demo",
		EvidenceVersion: 5, ReportEvidenceVersion: 3, // 曾经触发「待更新」提示的漂移
		TrafficBindings: []db.FindingTrafficBinding{{
			ID: 7, Role: "proof", Note: "越权读取",
			Snapshot: db.TrafficEvidenceSnapshot{Method: "GET", URL: "https://t.example.com/api/x", Status: 200},
		}},
	}
	for _, out := range []string{FindingsMarkdown([]*db.DBFinding{f}, time.Now()), SingleFindingMarkdown(f, time.Now())} {
		for _, banned := range []string{"证据版本", "绑定数量", "待更新"} {
			if strings.Contains(out, banned) {
				t.Fatalf("export contains process metadata %q:\n%s", banned, out)
			}
		}
		if !strings.Contains(out, "证明") {
			t.Fatalf("binding role should render in Chinese:\n%s", out)
		}
		if strings.Contains(out, "proof") {
			t.Fatalf("binding role leaked the internal English name:\n%s", out)
		}
	}
}
