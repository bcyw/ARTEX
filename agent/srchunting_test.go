package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHuntingFocusGuidanceInjection 锁「挖掘方向」节 + 文末「机器可查目录」
// 随收取标准同机制注入 guidance（票 01：目录块是类型归属与上限的唯一机器来源）。
func TestHuntingFocusGuidanceInjection(t *testing.T) {
	g := findingGuidanceWithStandards("")
	for _, want := range []string{
		"挖掘方向", "可收性 × 危害", "规范类型名", "触发启发式",
		"注入类", "命令执行与反序列化", "SSRF", "认证绕过与账户接管",
		"存储型 XSS", "文件上传 getshell", "业务逻辑",
		"越权", "同类上限", "别名折叠", "自成一桶", "没有类型化意图锚定时",
		"机器可查目录", "~~~types",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance 缺少收取标准内容: %q", want)
		}
	}
}

// TestSrcTypeCatalogDefaults 锁机器可查目录的默认值：8 个 collect: yes 类型
// 按书写序在前、明确不收类型在后，同类上限默认 3，每条都有证明物、
// collect: no 条目都有止损文案（上报被拒时引用）。
func TestSrcTypeCatalogDefaults(t *testing.T) {
	c := srcCatalog()
	wantCollect := []string{
		"注入类", "命令执行与反序列化", "SSRF", "认证绕过与账户接管",
		"存储型 XSS", "文件上传 getshell", "业务逻辑", "越权",
	}
	if c.Cap != 3 {
		t.Errorf("同类上限 = %d, want 3", c.Cap)
	}
	if len(c.Entries) < len(wantCollect) {
		t.Fatalf("目录条目 %d 条，少于可收类型 %d 条", len(c.Entries), len(wantCollect))
	}
	for i, want := range wantCollect {
		e := c.Entries[i]
		if e.Name != want {
			t.Errorf("目录[%d].Name = %q, want %q", i, e.Name, want)
		}
		if !e.Collect {
			t.Errorf("目录[%d] %q 应为 collect: yes", i, e.Name)
		}
	}
	for i, e := range c.Entries {
		if e.Proof == "" {
			t.Errorf("目录[%d] %q 缺少 proof（危害最小证明物）", i, e.Name)
		}
		if i >= len(wantCollect) && e.Collect {
			t.Errorf("目录[%d] %q 应为 collect: no（排在可收类型之后）", i, e.Name)
		}
		if !e.Collect && e.Stop == "" {
			t.Errorf("目录[%d] %q 缺少 stop 拒收文案", i, e.Name)
		}
	}
	// 派生视图与目录同源：Types 覆盖全部条目、Fold 非空、Cap 同步。
	f := srcHunting()
	if len(f.Types) != len(c.Entries) {
		t.Errorf("派生 Types 长度 = %d, want %d", len(f.Types), len(c.Entries))
	}
	if len(f.Fold) == 0 {
		t.Fatal("派生 Fold 为空")
	}
	if f.Cap != c.Cap {
		t.Errorf("派生 Cap = %d, want %d", f.Cap, c.Cap)
	}
	// 明确不收的类型必须可被 lookup 命中且 Collect=false（上报期拒收依据）。
	for _, name := range []string{"短信轰炸与无频控发码", "仅凭状态码报错响应差异", "理论 IDOR 无数据证明"} {
		e, ok := c.lookup(name)
		if !ok || e.Collect {
			t.Errorf("lookup(%q) = %+v, %v; want 命中且 collect: no", name, e, ok)
		}
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
		// 明确不收类型也折叠到规范桶（上报期据此拒收）。
		{"短信轰炸", "短信轰炸与无频控发码"},
		{"sms_bombing", "短信轰炸与无频控发码"},
		{"仅凭状态码", "仅凭状态码报错响应差异"},
		{"理论IDOR", "理论 IDOR 无数据证明"},
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
	// 导出入口（票 05）：供 server 呈现层把原始写法折叠到规范桶。导出与内部
	// 同一来源,断言两个代表写法与未覆盖写法,防将来导出口径漂移。
	if got := SrcFoldVulnClass("sql_injection"); got != "注入类" {
		t.Errorf("SrcFoldVulnClass(sql_injection) = %q, want 注入类", got)
	}
	if got := SrcFoldVulnClass("GraphQL 滥用"); got != "graphql滥用" {
		t.Errorf("SrcFoldVulnClass(未覆盖写法) = %q, want 归一形自成一桶", got)
	}
}

// TestSrcHuntingOverrideAndHotReload 锁热载与容错（票 01 验收：目录块改动后
// 重启进程即生效；自定义平台口径无机器可查区时优雅回退——零词表 + 默认上限，
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
	write("自定义标准正文\n\n~~~types\ncap: 5\ntype: 甲类\ncollect: yes\naliases: foo bar\nproof: 证明甲\nsignals: 信号甲\nstop: 止损甲\n\ntype: 乙类\ncollect: no\naliases: baz\nproof: 证明乙\nsignals: 信号乙\nstop: 止损乙\n~~~\n")
	c := srcCatalog()
	if c.Cap != 5 {
		t.Errorf("自定义 cap = %d, want 5", c.Cap)
	}
	if len(c.Entries) != 2 {
		t.Fatalf("自定义目录条目 = %d, want 2", len(c.Entries))
	}
	if c.Entries[0].Name != "甲类" || !c.Entries[0].Collect {
		t.Errorf("条目[0] = %+v, want 甲类/collect: yes", c.Entries[0])
	}
	if c.Entries[1].Name != "乙类" || c.Entries[1].Collect {
		t.Errorf("条目[1] = %+v, want 乙类/collect: no", c.Entries[1])
	}
	if c.Entries[1].Stop != "止损乙" {
		t.Errorf("collect: no 条目 stop = %q, want 止损乙", c.Entries[1].Stop)
	}
	if got := srcFoldVulnClass("BAR"); got != "甲类" {
		t.Errorf("自定义别名折叠 BAR = %q, want 甲类", got)
	}
	if got := srcFoldVulnClass("FOO"); got != "甲类" {
		t.Errorf("别名大小写变体折叠 = %q, want 甲类", got)
	}
	if got := srcFoldVulnClass("BAZ"); got != "乙类" {
		t.Errorf("collect: no 别名折叠 BAZ = %q, want 乙类", got)
	}

	// 热改：改文件后下一次调用即生效（比重启更宽松，重启天然满足）。
	write("自定义标准正文\n\n~~~types\ncap: 7\ntype: 甲类\ncollect: yes\naliases: foo\nproof: p\n\ntype: 丙类\ncollect: yes\naliases: qux\nproof: p\n~~~\n")
	f := srcHunting()
	if f.Cap != 7 {
		t.Errorf("热改后 cap = %d, want 7", f.Cap)
	}
	if len(f.Types) != 2 || f.Types[0] != "甲类" || f.Types[1] != "丙类" {
		t.Errorf("热改后规范名清单 = %v, want [甲类 丙类]", f.Types)
	}

	// 无机器可查区的自定义标准：回退零词表 + 默认上限 3，不拒收。
	write("只有正文，没有机器可查区\n")
	c = srcCatalog()
	if c.Cap != srcHuntingCapDefault {
		t.Errorf("无块时 cap = %d, want 默认 %d", c.Cap, srcHuntingCapDefault)
	}
	if len(c.Entries) != 0 {
		t.Errorf("无块时目录应为空, got %v", c.Entries)
	}
	if got := srcFoldVulnClass("任意新写法"); got != "任意新写法" {
		t.Errorf("无块时折叠 = %q, want 自成一桶", got)
	}

	// 容错：非法 cap、无冒号行、空键行、空 type 名、未知键一律跳过，块整体仍
	// 可解析；多个合法 cap 行以最后为准（热改口径语义）。
	write("~~~types\ncap: abc\ncap: -1\ncap: 2\n没有冒号的行\n: 空键\ntype: \nunknown_key: x\ntype: 乙类\ncollect: no\nstop: 止损\n~~~\n")
	c = srcCatalog()
	if c.Cap != 2 {
		t.Errorf("容错后 cap = %d, want 2（非法行忽略、合法行取最后）", c.Cap)
	}
	if len(c.Entries) != 1 || c.Entries[0].Name != "乙类" {
		t.Errorf("容错后目录 = %+v, want [乙类]", c.Entries)
	}
	if got := srcFoldVulnClass("乙类"); got != "乙类" {
		t.Errorf("无别名桶自身写法应命中本桶, got %q", got)
	}
	if got := srcFoldVulnClass("别的"); got != "别的" {
		t.Errorf("容错块未覆盖写法 = %q, want 自成一桶", got)
	}
}
