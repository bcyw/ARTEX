package agent

import (
	"os"
	"strings"
	"testing"
)

func TestSrcFindingBlocked(t *testing.T) {
	cases := []struct {
		desc               string
		vulnclass, name    string
		summary            string
		evidence           string
		description        string
		wantBlocked        bool
		wantReasonNonEmpty bool
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
		// 否定句不算升级证据:「无升级证据」包含字面标记,不能放行。
		{"无升级证据否定句不放行", "weak_password", "", "无升级证据,但危害很大", "", "", true, true},
		{"未提供升级证据不放行", "weak_password", "", "未提供升级证据", "", "", true, true},
		// 一票否决关键词只扫声明字段:evidence 里上下文性提及不拦截。
		{"证据里排除点击劫持不误杀", "idor", "水平越权", "展示了他人订单", "已排除点击劫持可能", "", false, false},
		{"证据里提及指纹不误杀", "sqli", "SQL注入", "注出库名", "响应中的指纹识别特征仅用于定位版本", "", false, false},
		// #1 反射 XSS(无敏感操作)与 #2 低危 CSRF。
		{"反射XSS拦截", "reflected_xss", "反射XSS", "搜索参数回显可弹窗", "", "", true, true},
		{"反射型XSS中文类名拦截", "反射型XSS", "", "", "", "", true, true},
		{"CSRF类名拦截", "csrf", "CSRF改资料", "", "", "", true, true},
		{"跨站请求伪造关键词拦截", "other", "跨站请求伪造", "可修改个人昵称", "", "", true, true},
		{"CSRF触达敏感操作升级放行", "csrf", "CSRF改绑手机", "升级证据：可触达改绑手机号操作", "", "", false, false},
		// #4 信息泄露具体形态。
		{"目录列表拦截", "directory_listing", "目录列表", "", "", "", true, true},
		{"git泄露拦截", "other", ".git泄露", "仓库目录可下载", "", "", true, true},
		{"phpinfo拦截", "phpinfo", "", "", "", "", true, true},
		{"源码泄露升级放行", "source_leak", "源码泄露", "升级证据：从泄露源码还原出注入点并实际利用", "", "", false, false},
		// #6/#7/#10 只拦显式自称理论/无回显的形态;已证实的不拦。
		{"理论IDOR拦截", "idor", "理论IDOR", "推测存在越权", "", "", true, true},
		{"疑似越权拦截", "other", "疑似越权", "未验证他人数据", "", "", true, true},
		{"已证实越权不拦", "idor", "水平越权", "B的token读到A的订单且内容一致", "", "", false, false},
		{"无回显SSRF拦截", "ssrf", "无回显SSRF", "仅DNSlog出网", "", "", true, true},
		{"仅DNSlog拦截", "ssrf", "SSRF", "仅dnslog验证出网", "", "", true, true},
		{"回显SSRF不拦", "ssrf", "SSRF读到内网元数据", "返回云元数据含凭据", "", "", false, false},
		{"可能存在未授权拦截", "other", "可能存在未授权", "接口疑似未授权", "", "", true, true},
		// 连写归一:下划线/空格/连字符写法同形匹配。
		{"用户名枚举空格英文拦截", "other", "Username Enumeration", "响应差异可枚举", "", "", true, true},
		{"反射XSS连字符拦截", "other", "Reflected-XSS", "", "", "", true, true},
		// #12 短信轰炸/无频控发码:拦截 + 升级放行。
		{"短信轰炸拦截", "sms_bombing", "短信轰炸", "无频控可向任意手机号发码", "", "", true, true},
		{"短信轰炸中文关键词拦截", "other", "验证码接口短信轰炸", "匿名可跨号下发", "", "", true, true},
		{"短信轰炸升级放行", "sms_bombing", "短信轰炸", "升级证据：发码链配合重置缺陷实际接管任意账户", "", "", false, false},
		{"正常验证码绕过不误杀", "auth_bypass", "验证码回显导致任意账户接管", "响应体回显验证码可登录他人账号", "", "", false, false},
		// #13 仅凭状态码/报错/响应差异:拦显式自称形态,已证实的不拦。
		{"仅状态码拦截", "other", "接口异常", "仅凭状态码差异判定未授权", "", "", true, true},
		{"仅响应差异拦截", "other", "响应差异", "仅响应差异可区分账号", "", "", true, true},
		{"状态码差异已证实不拦", "idor", "水平越权", "403变200且返回他人订单数据", "", "", false, false},
		{"布尔盲注不误杀", "sqli", "布尔盲注", "时间差+注出库名内容", "", "", false, false},
		// #11 扩展:手机号枚举/存在性。
		{"手机号枚举拦截", "other", "手机号枚举", "注册接口可探测手机号已注册", "", "", true, true},
		{"手机号存在性英文拦截", "phone_enumeration", "", "", "", "", true, true},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			blocked, reason := SrcFindingBlocked(SrcFindingTexts{
				VulnClass: c.vulnclass, Name: c.name, Summary: c.summary,
				Evidence: c.evidence, Description: c.description,
			})
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
	if !strings.Contains(g, "拦截进隔离区") {
		t.Fatal("guidance 缺少硬闸行为说明")
	}
	if !strings.Contains(g, "复测纪律") {
		t.Fatal("guidance 缺少复测纪律段")
	}
	if !strings.Contains(g, "中高危挖掘导向") {
		t.Fatal("guidance 缺少中高危挖掘导向")
	}
	if !strings.Contains(g, "反序列化") || !strings.Contains(g, "SSRF") || !strings.Contains(g, "模板注入") {
		t.Fatal("guidance 高危类别覆盖不全")
	}
	if strings.Contains(g, "短信轰炸、批量注册") {
		t.Fatal("guidance 挖掘导向仍把短信轰炸/批量注册列为挖掘目标")
	}
	if !strings.Contains(g, "不挖清单") {
		t.Fatal("guidance 缺少不挖清单段")
	}
	if !strings.Contains(g, "响应差异不是漏洞") {
		t.Fatal("guidance 缺少响应差异止损纪律")
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
