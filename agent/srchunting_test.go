package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHuntingFocusGuidanceInjection 锁「挖掘方向」节随收取标准同机制注入
// guidance（票 01：节文本进 agent 提示，七类规范类型名 + 越权 + 触发启发式 +
// 同类上限 + 折叠表 + 可收性×危害优先级说明）。
func TestHuntingFocusGuidanceInjection(t *testing.T) {
	g := findingGuidanceWithStandards("")
	for _, want := range []string{
		"挖掘方向", "可收性 × 危害", "规范类型名", "触发启发式",
		"注入类", "命令执行与反序列化", "SSRF", "认证绕过与账户接管",
		"存储型 XSS", "文件上传 getshell", "业务逻辑",
		"越权", "同类上限", "别名折叠", "自成一桶", "绝不拒收",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance 缺少挖掘方向节内容: %q", want)
		}
	}
}

// TestSrcHuntingFocusDefaults 锁机器可查三量的默认值：规范名清单（优先级序，
// 七类在前、越权垫底）、折叠映射、同类上限默认 3。默认文本与热载文件语义同步
// 维护，此处跑的是内嵌默认（单测环境无路径覆盖）。
func TestSrcHuntingFocusDefaults(t *testing.T) {
	f := srcHunting()
	wantTypes := []string{
		"注入类", "命令执行与反序列化", "SSRF", "认证绕过与账户接管",
		"存储型 XSS", "文件上传 getshell", "业务逻辑", "越权",
	}
	if len(f.Types) != len(wantTypes) {
		t.Fatalf("规范名清单长度 = %d, want %d (%v)", len(f.Types), len(wantTypes), f.Types)
	}
	for i, want := range wantTypes {
		if f.Types[i] != want {
			t.Errorf("规范名清单[%d] = %q, want %q", i, f.Types[i], want)
		}
	}
	if f.Cap != 3 {
		t.Errorf("同类上限 = %d, want 3", f.Cap)
	}
	if len(f.Fold) == 0 {
		t.Fatal("折叠映射为空")
	}
}

// TestSrcFoldVulnClass 锁折叠行为（票 01 验收项）：
//   - 折叠表覆盖的常见写法（含票面示例 sql_injection / SQL 注入 / SQLi）折叠到同一规范桶；
//   - 规范名自身写法也命中本桶；
//   - 表未覆盖的新写法以归一形自成一桶、照常计数、绝不拒收；
//   - 未覆盖写法的大小写/空白/连字符变体归入同一自成桶（不碎片化计数）。
func TestSrcFoldVulnClass(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 注入类：票面示例三写法同桶。
		{"sql_injection", "注入类"},
		{"SQL 注入", "注入类"},
		{"SQLi", "注入类"},
		{"SQL-INJECTION", "注入类"},
		{"注入类", "注入类"},
		{"ssti", "注入类"},
		{"模板注入", "注入类"},
		// 命令执行与反序列化。
		{"rce", "命令执行与反序列化"},
		{"RCE", "命令执行与反序列化"},
		{"反序列化", "命令执行与反序列化"},
		{"command_injection", "命令执行与反序列化"},
		{"命令执行", "命令执行与反序列化"},
		// SSRF。
		{"ssrf", "SSRF"},
		{"SSRF", "SSRF"},
		{"服务端请求伪造", "SSRF"},
		// 认证绕过与账户接管。
		{"auth_bypass", "认证绕过与账户接管"},
		{"认证绕过", "认证绕过与账户接管"},
		{"account_takeover", "认证绕过与账户接管"},
		// 存储型 XSS。
		{"stored_xss", "存储型 XSS"},
		{"存储型XSS", "存储型 XSS"},
		{"存储 XSS", "存储型 XSS"},
		{"存储型 XSS", "存储型 XSS"},
		// 文件上传 getshell。
		{"file_upload", "文件上传 getshell"},
		{"文件上传", "文件上传 getshell"},
		{"webshell", "文件上传 getshell"},
		// 业务逻辑。
		{"business_logic", "业务逻辑"},
		{"逻辑漏洞", "业务逻辑"},
		// 越权（合法方向，独立规范桶）。
		{"idor", "越权"},
		{"IDOR", "越权"},
		{"水平越权", "越权"},
		{"垂直越权", "越权"},
		{"unauth", "越权"},
		{"未授权", "越权"},
		// 表未覆盖的新写法：以归一形自成一桶，不拒收。
		{"GraphQL 滥用", "graphql滥用"},
		{"graphql_abuse", "graphqlabuse"},
		{"GraphQL-Abuse", "graphqlabuse"},
		{"GraphQL Abuse", "graphqlabuse"},
	}
	for _, c := range cases {
		if got := srcFoldVulnClass(c.in); got != c.want {
			t.Errorf("srcFoldVulnClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 空串归一后仍为空，不误挂任何桶。
	if got := srcFoldVulnClass("   "); got != "" {
		t.Errorf("srcFoldVulnClass(空白串) = %q, want 空串", got)
	}
}

// TestSrcHuntingOverrideAndHotReload 锁热载与容错（票 01 验收：节改动后重启
// 进程即生效；自定义平台口径无机器可查区时优雅回退——零词表 + 默认上限，
// 一切写法自成一桶，绝不拒收）。
func TestSrcHuntingOverrideAndHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src-acceptance.md")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	SrcAcceptancePath(path)
	defer SrcAcceptancePath("")

	// 自定义机器可查区：cap 与词表都按文件走。
	write("自定义标准正文\n\n~~~hunting\ncap: 5\n甲类: foo bar\n~~~\n")
	f := srcHunting()
	if f.Cap != 5 {
		t.Errorf("自定义 cap = %d, want 5", f.Cap)
	}
	if len(f.Types) != 1 || f.Types[0] != "甲类" {
		t.Errorf("自定义规范名清单 = %v, want [甲类]", f.Types)
	}
	if got := srcFoldVulnClass("BAR"); got != "甲类" {
		t.Errorf("自定义别名折叠 BAR = %q, want 甲类", got)
	}
	if got := srcFoldVulnClass("FOO"); got != "甲类" {
		t.Errorf("别名大小写变体折叠 = %q, want 甲类", got)
	}

	// 热改：改文件后下一次调用即生效（比重启更宽松，重启天然满足）。
	write("自定义标准正文\n\n~~~hunting\ncap: 7\n甲类: foo\n乙类: baz\n~~~\n")
	f = srcHunting()
	if f.Cap != 7 {
		t.Errorf("热改后 cap = %d, want 7", f.Cap)
	}
	if len(f.Types) != 2 || f.Types[0] != "甲类" || f.Types[1] != "乙类" {
		t.Errorf("热改后规范名清单 = %v, want [甲类 乙类]", f.Types)
	}

	// 无机器可查区的自定义标准：回退零词表 + 默认上限 3，不拒收。
	write("只有正文，没有机器可查区\n")
	f = srcHunting()
	if f.Cap != srcHuntingCapDefault {
		t.Errorf("无块时 cap = %d, want 默认 %d", f.Cap, srcHuntingCapDefault)
	}
	if len(f.Types) != 0 || len(f.Fold) != 0 {
		t.Errorf("无块时词表应为空, got types=%v fold=%v", f.Types, f.Fold)
	}
	if got := srcFoldVulnClass("任意新写法"); got != "任意新写法" {
		t.Errorf("无块时折叠 = %q, want 自成一桶", got)
	}

	// 容错：非法 cap 行、无冒号行、空键行、无别名行一律跳过，块整体仍可解析；
	// 多个合法 cap 行以最后为准（热改口径语义）。
	write("~~~hunting\ncap: abc\ncap: -1\ncap: 2\n没有冒号的行\n: 空键\n乙类: \n~~~\n")
	f = srcHunting()
	if f.Cap != 2 {
		t.Errorf("容错后 cap = %d, want 2（非法行忽略、合法行取最后）", f.Cap)
	}
	if len(f.Types) != 1 || f.Types[0] != "乙类" {
		t.Errorf("容错后规范名清单 = %v, want [乙类]", f.Types)
	}
	if got := srcFoldVulnClass("乙类"); got != "乙类" {
		t.Errorf("无别名桶自身写法应命中本桶, got %q", got)
	}
	if got := srcFoldVulnClass("别的"); got != "别的" {
		t.Errorf("容错块未覆盖写法 = %q, want 自成一桶", got)
	}
}
