package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// TestFindingStatsFoldsVulnClassCountsIntoCanonicalBuckets 锁票 05 的呈现层
// 折叠行为：stats 端点的类型分布按规范桶名合并（sql_injection 与「SQL 注入」
// 是同一桶「注入类」，不产生重复行），计数为桶内原始写法之和，confirmed 单独
// 计数；Values 回填桶内原始写法清单（前端把桶选项展开成列表筛选）；
// vulnclasses 保持原始清单（既有选中项校验兼容，不回归）。
func TestFindingStatsFoldsVulnClassCountsIntoCanonicalBuckets(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	marker := fmt.Sprintf("__server_stats_fold_%d__", time.Now().UnixNano())
	defer func() { _, _ = m.pg.Exec(`DELETE FROM findings WHERE vulnclass IN ($1,'sql_injection',$2,$3)`, marker, "SQL 注入", "GraphQL 滥用") }()

	task, err := m.CreateTask("stats fold task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteTask(mustTaskID(t, task.ID)) }()
	taskID := mustTaskID(t, task.ID)

	seed := []struct {
		vulnclass string
		severity  string
		status    string
	}{
		{"sql_injection", db.SeverityCritical, db.FindingPending},
		{"SQL 注入", db.SeverityHigh, db.FindingConfirmed},
		{"GraphQL 滥用", db.SeverityMedium, db.FindingPending},
	}
	var ids []int64
	for _, s := range seed {
		id, err := m.pg.AddFinding(taskID, 0, s.vulnclass, "", s.severity, "summary", "poc", "test", nil)
		if err != nil {
			t.Fatalf("AddFinding(%s): %v", s.vulnclass, err)
		}
		if _, err := m.pg.SetFindingStatus(id, s.status); err != nil {
			t.Fatalf("SetFindingStatus(%s): %v", s.vulnclass, err)
		}
		ids = append(ids, id)
	}
	// 干扰行:另一个任务里的同桶写法 + 未知桶,验证合并是全表口径。
	if _, err := m.pg.AddFinding(0, 0, "SQLi", "", db.SeverityLow, "summary", "poc", "test", nil); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.Exec(`DELETE FROM findings WHERE vulnclass='SQLi'`) }()

	s := &Server{m: m}
	rec := httptest.NewRecorder()
	s.findingStats(rec, httptest.NewRequest(http.MethodGet, "/api/exploration/findings/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", rec.Code, rec.Body.String())
	}
	var st struct {
		VulnClasses      []string `json:"vulnclasses"`
		VulnClassCounts  []struct {
			VulnClass string   `json:"vulnclass"`
			Count     int      `json:"count"`
			Confirmed int      `json:"confirmed"`
			Values    []string `json:"values"`
		} `json:"vulnclass_counts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}

	// 注入类桶:三写法(sql_injection / SQL 注入 / SQLi)合并为一行,不碎片化。
	var injection *struct {
		VulnClass string   `json:"vulnclass"`
		Count     int      `json:"count"`
		Confirmed int      `json:"confirmed"`
		Values    []string `json:"values"`
	}
	for i := range st.VulnClassCounts {
		if st.VulnClassCounts[i].VulnClass == agent.SrcFoldVulnClass("sql_injection") {
			injection = &st.VulnClassCounts[i]
		}
	}
	if injection == nil {
		t.Fatalf("stats vulnclass_counts missing canonical bucket 注入类: %+v", st.VulnClassCounts)
	}
	if injection.Count != 3 {
		t.Fatalf("注入类桶 count=%d, want 3 (sql_injection+SQL 注入+SQLi)", injection.Count)
	}
	if injection.Confirmed != 1 {
		t.Fatalf("注入类桶 confirmed=%d, want 1", injection.Confirmed)
	}
	gotValues := map[string]bool{}
	for _, v := range injection.Values {
		gotValues[v] = true
	}
	for _, want := range []string{"sql_injection", "SQL 注入", "SQLi"} {
		if !gotValues[want] {
			t.Fatalf("注入类桶 values 缺 %q: %+v", want, injection.Values)
		}
	}

	// 未知写法自成一桶:归一形为桶名、count=1,values 含原写法。
	var graphql *struct {
		VulnClass string   `json:"vulnclass"`
		Count     int      `json:"count"`
		Confirmed int      `json:"confirmed"`
		Values    []string `json:"values"`
	}
	for i := range st.VulnClassCounts {
		if st.VulnClassCounts[i].VulnClass == agent.SrcFoldVulnClass("GraphQL 滥用") {
			graphql = &st.VulnClassCounts[i]
		}
	}
	if graphql == nil {
		t.Fatalf("stats vulnclass_counts missing self-bucket for unknown class: %+v", st.VulnClassCounts)
	}
	if graphql.Count != 1 || graphql.Confirmed != 0 || len(graphql.Values) != 1 || graphql.Values[0] != "GraphQL 滥用" {
		t.Fatalf("未知写法自成一桶 = %+v, want count=1 confirmed=0 values=[GraphQL 滥用]", graphql)
	}

	// 既有兼容:vulnclasses 仍是原始写法清单(选中项校验不回归)。
	for _, want := range []string{"sql_injection", "SQL 注入", "SQLi", "GraphQL 滥用"} {
		found := false
		for _, vc := range st.VulnClasses {
			if vc == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("vulnclasses 原始清单缺 %q: %v", want, st.VulnClasses)
		}
	}
	// 桶排序契约:count 降序,并列按桶名升序(与 db 层一致)。
	for i := 1; i < len(st.VulnClassCounts); i++ {
		prev, cur := st.VulnClassCounts[i-1], st.VulnClassCounts[i]
		if prev.Count < cur.Count || (prev.Count == cur.Count && strings.Compare(prev.VulnClass, cur.VulnClass) > 0) {
			t.Fatalf("vulnclass_counts 未按 count desc/name asc 排序: %+v", st.VulnClassCounts)
		}
	}
}

// TestFindingsListFilterExpandsCanonicalBucket 锁票面「别名不产生重复行」的
// 消费端行为：选中规范桶（如「注入类」）时列表筛选按桶内 Values 多值展开，
// 三个原始写法的行全部返回；选中未知桶时回退单值精确匹配。
func TestFindingsListFilterExpandsCanonicalBucket(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatalf("SQLite unavailable (%v)", err)
	}
	t.Cleanup(func() { m.Close() })
	marker := fmt.Sprintf("__server_bucket_expand_%d__", time.Now().UnixNano())
	defer func() { _, _ = m.pg.Exec(`DELETE FROM findings WHERE vulnclass IN ($1,'sql_injection',$2)`, marker, "SQL 注入") }()

	task, err := m.CreateTask("bucket expand task", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.pg.DeleteTask(mustTaskID(t, task.ID)) }()
	taskID := mustTaskID(t, task.ID)

	for _, vc := range []string{"sql_injection", "SQL 注入", marker} {
		if _, err := m.pg.AddFinding(taskID, 0, vc, "", db.SeverityHigh, "summary", "poc", "test", nil); err != nil {
			t.Fatalf("AddFinding(%s): %v", vc, err)
		}
	}

	s := &Server{m: m}
	// 模拟前端:选中「注入类」桶 → 拿 stats 的 Values 展开成多值筛选参数。
	q := url.Values{}
	q.Set("vulnclass", "sql_injection,SQL 注入")
	req := httptest.NewRequest(http.MethodGet, "/api/exploration/findings?"+q.Encode()+"&page=1&limit=50", nil)
	rec := httptest.NewRecorder()
	s.findings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("findings status=%d body=%s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items []struct {
			VulnClass string `json:"vulnclass"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Fatalf("bucket-expanded filter total=%d, want 2 (sql_injection + SQL 注入)", page.Total)
	}
	for _, item := range page.Items {
		if item.VulnClass == marker {
			t.Fatalf("marker row leaked into bucket-expanded filter: %+v", page.Items)
		}
	}

	// 未知桶(无 Values)回退单值精确匹配,行为与旧版一致。
	req = httptest.NewRequest(http.MethodGet, "/api/exploration/findings?vulnclass="+url.QueryEscape(marker)+"&page=1&limit=50", nil)
	rec = httptest.NewRecorder()
	s.findings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("findings status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("single-value filter total=%d, want 1", page.Total)
	}
}
