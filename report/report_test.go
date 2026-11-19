package report

import (
	"strings"
	"testing"
)

func TestMarkdownRendersDeliverableSkeleton(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{{
		Name:        "a.example.com 存在订单接口越权读取他人敏感信息漏洞",
		VulnClass:   "越权访问（IDOR）",
		Severity:    "high",
		Assets:      []string{"a.example.com"},
		Description: "订单接口只校验登录态，不校验订单归属。攻击者修改订单号即可读取他人订单。",
		Steps: []Step{{
			Role:     "proof",
			Note:     "用 B 的 token 读取 A 的订单",
			URL:      "https://api.example.com/api/orders/1001",
			Request:  "GET /api/orders/1001 HTTP/1.1\r\nHost: api.example.com\r\nCookie: token=B\r\n\r\n",
			Response: "HTTP 200\r\nContent-Type: application/json\r\n\r\n{}",
		}},
		Impact:      "1. 读取他人订单中的手机号与地址。",
		Remediation: "1. 查询订单时按会话用户校验 order.user_id。",
	}}})

	for _, want := range []string{
		"# a.example.com 存在订单接口越权读取他人敏感信息漏洞",
		"## 漏洞等级\n\n高危",
		"## 漏洞类型\n\n越权访问（IDOR）",
		"## 漏洞影响资产\n\na.example.com",
		"## 漏洞URL\n\nhttps://api.example.com/api/orders/1001",
		"## 漏洞描述\n\n订单接口只校验登录态",
		"## 漏洞复现步骤（POC）",
		"### Step 1（证明）",
		"用 B 的 token 读取 A 的订单",
		"```http\nGET /api/orders/1001 HTTP/1.1",
		"```http\nHTTP 200",
		"## 漏洞危害\n\n1. 读取他人订单中的手机号与地址。",
		"## 修复建议\n\n1. 查询订单时按会话用户校验 order.user_id。",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q\n---\n%s", want, md)
		}
	}

	for _, unwanted := range []string{"任务目标", "任务 ID", "生成时间", "测试资产范围", "待补充", "未绑定", "我使用了"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("report must not contain %q\n---\n%s", unwanted, md)
		}
	}
}

func TestMarkdownOmitsEmptySections(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{{
		VulnClass:   "信息泄露",
		Severity:    "low",
		Description: "接口返回内部版本号。",
	}}})

	for _, unwanted := range []string{"## 漏洞等级\n\n\n", "## 测试账号与会话上下文", "## 漏洞复现步骤", "## 漏洞危害", "## 修复建议", "## 漏洞影响资产", "## 漏洞URL"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("empty section %q must be omitted\n---\n%s", unwanted, md)
		}
	}
	for _, want := range []string{"# 信息泄露", "## 漏洞等级\n\n低危", "## 漏洞描述"} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q\n---\n%s", want, md)
		}
	}
}

func TestMarkdownDedupesVulnerabilityURLsInStepOrder(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{{
		Name:     "x",
		Severity: "medium",
		Steps: []Step{
			{URL: "https://api.example.com/a", Role: "baseline"},
			{URL: "https://api.example.com/b", Role: "proof"},
			{URL: "https://api.example.com/a", Role: "verification"},
		},
	}}})

	start := strings.Index(md, "## 漏洞URL")
	if start < 0 {
		t.Fatalf("missing URL section\n%s", md)
	}
	block := md[start:]
	if end := strings.Index(block, "\n## "); end >= 0 {
		block = block[:end]
	}
	if strings.Count(block, "https://api.example.com/a") != 1 {
		t.Errorf("duplicate URL must collapse once\n%s", block)
	}
	if strings.Index(block, "/a") > strings.Index(block, "/b") {
		t.Errorf("URLs must keep step order\n%s", block)
	}
}

func TestMarkdownSeparatesMultipleFindings(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{
		{Name: "low one", Severity: "low"},
		{Name: "critical one", Severity: "critical"},
	}})

	if strings.Index(md, "# critical one") > strings.Index(md, "# low one") {
		t.Errorf("findings must be sorted critical first\n%s", md)
	}
	if !strings.Contains(md, "---\n") {
		t.Errorf("findings must be separated\n%s", md)
	}
}

func TestMarkdownFallsBackToPoCWithoutBindings(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{{
		Name:     "x",
		Severity: "high",
		PoC:      "curl -i https://a.example.com/api/orders/1001",
	}}})

	if !strings.Contains(md, "## 漏洞复现步骤（POC）\n\n```\ncurl -i https://a.example.com/api/orders/1001\n```") {
		t.Errorf("unbound finding must keep its PoC text\n%s", md)
	}
	for _, unwanted := range []string{"未绑定", "待补充", "无流量"} {
		if strings.Contains(md, unwanted) {
			t.Errorf("missing data must stay unannotated, found %q\n%s", unwanted, md)
		}
	}
}

func TestMarkdownPrefersBoundPacketsOverPoCText(t *testing.T) {
	md := Markdown(Input{Findings: []Finding{{
		Name:     "x",
		Severity: "high",
		PoC:      "legacy poc text",
		Steps:    []Step{{Role: "proof", URL: "https://a.example.com/x", Request: "GET /x HTTP/1.1\r\nHost: a.example.com"}},
	}}})

	if strings.Contains(md, "legacy poc text") {
		t.Errorf("bound findings render packets, not the old PoC text\n%s", md)
	}
	if !strings.Contains(md, "### Step 1（证明）") {
		t.Errorf("bound step missing\n%s", md)
	}
}
