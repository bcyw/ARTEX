// Package report renders a deliverable Markdown report of confirmed findings.
//
// The report is a hand-over artifact: it is submitted to reviewers and copied
// verbatim to other agents for reproduction. It therefore carries no task
// metadata, no process narration and no placeholders — empty sections are
// omitted instead. Raw HTTP packets come from bound evidence snapshots; see
// docs/adr/0001-report-raw-from-evidence-snapshots.md.
package report

import (
	"fmt"
	"sort"
	"strings"
)

// Input bundles what the report needs.
type Input struct {
	Findings []Finding
}

// Finding is one confirmation-ready vulnerability.
type Finding struct {
	Name        string   // 漏洞名称;空时回退 VulnClass
	VulnClass   string   // 漏洞类型
	Severity    string   // critical|high|medium|low
	Assets      []string // 漏洞影响资产
	Description string   // 漏洞描述
	Summary     string   // 旧数据的描述兜底
	Session     string   // 测试账号与会话上下文;可选
	Steps       []Step   // 漏洞复现步骤,按复现顺序
	PoC         string   // 无绑定时使用的 PoC 原文
	Impact      string   // 漏洞危害
	Remediation string   // 修复建议
}

// Step is one reproduction step backed by a bound traffic snapshot.
type Step struct {
	Role     string // baseline|proof|verification|supporting
	Note     string // 该步做什么、证明了什么
	Method   string // 请求方法
	URL      string // 该请求对应的完整 URL
	Status   int    // 响应状态码;0 表示未知
	Request  string // 规范化后的 raw 请求;空表示没有可文本化的报文
	Response string // 规范化后的 raw 响应;空表示没有可文本化的报文
}

var roleLabels = map[string]string{
	"baseline":     "对照",
	"proof":        "证明",
	"verification": "复验",
	"supporting":   "支撑",
}

var sevLabels = map[string]string{
	"critical": "严重",
	"high":     "高危",
	"medium":   "中危",
	"low":      "低危",
	"info":     "信息",
}

// Markdown renders the report. Findings are ordered most severe first.
func Markdown(in Input) string {
	fs := append([]Finding(nil), in.Findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		return severityRank(fs[i].Severity) < severityRank(fs[j].Severity)
	})

	var b strings.Builder
	for i := range fs {
		if i > 0 {
			b.WriteString("---\n\n")
		}
		renderFinding(&b, fs[i])
	}
	return b.String()
}

func renderFinding(b *strings.Builder, f Finding) {
	title := nz(strings.TrimSpace(f.Name), nz(strings.TrimSpace(f.VulnClass), "未分类漏洞"))
	fmt.Fprintf(b, "# %s\n\n", title)

	section(b, "漏洞等级", severityLabel(f.Severity))
	section(b, "漏洞类型", f.VulnClass)
	section(b, "漏洞影响资产", strings.Join(trimAll(f.Assets), "\n"))
	if urls := uniqueURLs(f.Steps); len(urls) > 0 {
		section(b, "漏洞URL", strings.Join(urls, "\n"))
	}
	section(b, "漏洞描述", nz(f.Description, f.Summary))
	section(b, "测试账号与会话上下文", f.Session)
	if len(f.Steps) > 0 {
		renderSteps(b, f.Steps)
	} else {
		renderPoC(b, f.PoC)
	}
	section(b, "漏洞危害", f.Impact)
	section(b, "修复建议", f.Remediation)
}

// renderPoC keeps legacy findings reproducible: without bound packets the
// existing PoC text is the only evidence, so it is rendered verbatim. Nothing
// explains why there are no packets.
func renderPoC(b *strings.Builder, poc string) {
	poc = strings.TrimSpace(poc)
	if poc == "" {
		return
	}
	fmt.Fprintf(b, "## 漏洞复现步骤（POC）\n\n```\n%s\n```\n\n", strings.TrimRight(poc, "\r\n"))
}

// section writes a level-2 section, omitting it entirely when empty. The
// absence of a section is deliberate: a report must never explain what it
// could not include.
func section(b *strings.Builder, title, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	fmt.Fprintf(b, "## %s\n\n%s\n\n", title, body)
}

func renderSteps(b *strings.Builder, steps []Step) {
	if len(steps) == 0 {
		return
	}
	b.WriteString("## 漏洞复现步骤（POC）\n\n")
	for i, s := range steps {
		fmt.Fprintf(b, "### Step %d（%s）\n\n", i+1, roleLabel(s.Role))
		if line := stepLine(s); line != "" {
			fmt.Fprintf(b, "%s\n\n", line)
		}
		// A step without a text-safe packet keeps its context and drops the
		// block: a fabricated or placeholder packet is worse than none.
		if req := strings.TrimSpace(s.Request); req != "" {
			fmt.Fprintf(b, "```http\n%s\n```\n\n", strings.TrimRight(req, "\r\n"))
		}
		if resp := strings.TrimSpace(s.Response); resp != "" {
			fmt.Fprintf(b, "```http\n%s\n```\n\n", strings.TrimRight(resp, "\r\n"))
		}
		if s.Status > 0 {
			fmt.Fprintf(b, "结果：HTTP %d\n\n", s.Status)
		}
	}
}

// stepLine is the one-line "what + which URL" summary that opens a step. The
// binding note supplies the intent; the URL is appended unless it is already
// spelled out in the note.
func stepLine(s Step) string {
	note := strings.TrimSpace(s.Note)
	target := strings.TrimSpace(s.URL)
	if method := strings.ToUpper(strings.TrimSpace(s.Method)); method != "" && target != "" {
		target = method + " " + target
	}
	switch {
	case note == "":
		return target
	case target == "" || strings.Contains(note, strings.TrimSpace(s.URL)):
		return note
	default:
		return note + "（" + target + "）"
	}
}

func severityLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if label, ok := sevLabels[s]; ok {
		return label
	}
	return sevLabels["info"]
}

func roleLabel(role string) string {
	if label, ok := roleLabels[strings.ToLower(strings.TrimSpace(role))]; ok {
		return label
	}
	return roleLabels["supporting"]
}

func uniqueURLs(steps []Step) []string {
	seen := make(map[string]bool, len(steps))
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		u := strings.TrimSpace(s.URL)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// severityRank orders findings for the report; anything unknown sorts last
// instead of being promoted to critical by a map zero value.
func severityRank(s string) int {
	if rank, ok := sevRank[strings.ToLower(strings.TrimSpace(s))]; ok {
		return rank
	}
	return 5
}

func nz(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
