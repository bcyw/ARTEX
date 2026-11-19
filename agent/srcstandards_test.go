package agent

import (
	"os"
	"strings"
	"testing"
)

func TestSrcFindingBlocked(t *testing.T) {
	cases := []struct {
		desc                          string
		vulnclass, name, summary      string
		evidence, description         string
		wantBlocked                   bool
		wantReasonNonEmpty            bool
	}{
		{"正常SQL注入", "sqli", "SQL注入", "union查询返回用户数据", "响应包含用户表数据", "", false, false},
		{"正常越权", "idor", "水平越权", "展示了其他账户的订单", "", "", false, false},
		{"会话劫持是合法高危不误杀", "session_hijacking", "会话劫持", "接管了目标会话", "", "", false, false},
		{"点击劫持中文", "clickjacking", "点击劫持", "", "", "", true, true},
		{"英文类名指纹", "fingerprint", "", "", "", "", true, true},
		{"vulnclass版本披露", "version_disclosure", "", "", "", "", true, true},
		{"JSONP", "jsonp_hijacking", "", "", "", "", true, true},
		{"弱口令", "weak_password", "", "", "", "", true, true},
		{"Self-XSS", "self_xss", "", "", "", "", true, true},
		{"CRLF", "crlf_injection", "", "", "", "", true, true},
		{"摘要里带关键词", "other", "某漏洞", "本质是点击劫持问题", "", "", true, true},
		{"用户名枚举拦截", "info_disclosure", "用户名枚举", "响应差异可枚举账号", "", "", true, true},
		{"账号存在性英文拦截", "username_enumeration", "", "", "", "", true, true},
		// 一票否决类:写升级证据也不放行(#8/#9 无升级条件)。
		{"一票否决clickjacking不放行", "clickjacking", "", "升级证据：反射点位于支付页面上下文", "", "", true, true},
		{"一票否决指纹不放行", "other", "指纹识别", "升级证据：由指纹定位到已知利用链", "", "", true, true},
		// 普通黑名单类:升级证据放行,且 evidence/description 里写也算。
		{"升级证据放行", "weak_password", "", "升级证据：高权账户可横向影响", "", "", false, false},
		{"升级证据写在evidence也放行", "weak_password", "", "疑似默认口令", "升级证据：登录的是管理员账户并拿到后台权限", "", false, false},
		{"无升级证据字样不放行", "weak_password", "", "这个真的危害很大", "", "", true, true},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			blocked, reason := SrcFindingBlocked(c.vulnclass, c.name, c.summary, c.evidence, c.description)
			if blocked != c.wantBlocked {
				t.Fatalf("blocked = %v, want %v (reason=%q)", blocked, c.wantBlocked, reason)
			}
			if c.wantReasonNonEmpty && reason == "" {
				t.Fatal("expected non-empty reason")
			}
		})
	}
}

func TestFindingGuidanceWithStandards(t *testing.T) {
	g := findingGuidanceWithStandards("")
	if !strings.Contains(g, "SRC 漏洞收取标准") {
		t.Fatal("guidance 缺少 SRC 收取标准标题")
	}
	if !strings.Contains(g, "黑名单") {
		t.Fatal("guidance 缺少黑名单段")
	}
	if !strings.Contains(g, "拒绝入库") {
		t.Fatal("guidance 缺少硬闸行为说明")
	}
	if !strings.Contains(g, "中高危挖掘导向") {
		t.Fatal("guidance 缺少中高危挖掘导向")
	}
	if !strings.Contains(g, "反序列化") || !strings.Contains(g, "SSRF") || !strings.Contains(g, "模板注入") {
		t.Fatal("guidance 高危类别覆盖不全")
	}
}

func TestSrcAcceptanceOverridePath(t *testing.T) {
	dir := t.TempDir()
	custom := "自定义平台收取标准（测试覆盖）"
	path := dir + "/src-acceptance.md"
	if err := os.WriteFile(path, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	SrcAcceptancePath(path)
	defer SrcAcceptancePath("")
	if got := srcAcceptance(); got != custom {
		t.Fatalf("override 未生效: got %q", got)
	}
	// 不存在的路径 → 回退内嵌默认
	SrcAcceptancePath(dir + "/missing.md")
	if got := srcAcceptance(); !strings.Contains(got, "SRC 漏洞收取标准") {
		t.Fatalf("缺失文件未回退默认: got %q", got)
	}
}
