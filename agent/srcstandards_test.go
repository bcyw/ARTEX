package agent

import (
	"os"
	"strings"
	"testing"
)

// TestFindingGuidanceWithStandards 锁收取标准随 guidance 注入的骨架：正文
// 章节 + 文末机器可查目录（票 01 起类型归属与上限的唯一机器来源），且不再
// 携带旧版词表黑名单/隔离区口径。
func TestFindingGuidanceWithStandards(t *testing.T) {
	g := findingGuidanceWithStandards("")
	for _, want := range []string{
		"SRC 漏洞收取标准",
		"明确不收类型",
		"危害最小证明物",
		"硬门",
		"查重",
		"不挖清单",
		"挖掘方向",
		"定级纪律",
		"复测纪律",
		"机器可查目录",
		"~~~types",
		"cap: 3",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance 缺少收取标准内容: %q", want)
		}
	}
	// 类型中性行为纪律（ADR-0004：类型词表绝不进代码常量）。
	if !strings.Contains(g, "止损线") || !strings.Contains(g, "触发启发式") {
		t.Fatal("guidance 缺少类型中性行为纪律（触发启发式/止损线）")
	}
	if !strings.Contains(g, "响应差异不是漏洞") {
		t.Fatal("guidance 缺少响应差异止损纪律")
	}
	// 旧版上报期词表闸退场：guidance 不再描述「拦截进隔离区」。
	if strings.Contains(g, "隔离区") {
		t.Fatal("guidance 仍含旧版隔离区口径")
	}
	// 挖掘导向不把明确不收的类型列为挖掘目标（短信轰炸/批量注册只在
	// 「明确不收类型」「不挖清单」里出现，并指向 record_fact）。
	if strings.Contains(g, "短信轰炸、批量注册") {
		t.Fatal("guidance 挖掘导向仍把短信轰炸/批量注册列为挖掘目标")
	}
}

// TestSrcHighRiskHuntingTypeNeutral 锚定 ADR-0004「类型词表绝不进代码常量」：
// Go 内置导向常量瘦身为类型中性行为纪律，类型优先级清单只活在热载挖掘方向节。
func TestSrcHighRiskHuntingTypeNeutral(t *testing.T) {
	const c = srcHighRiskHunting
	for _, banned := range []string{"注入类", "SQL 注入", "反序列化", "SSRF", "模板注入", "文件上传", "越权", "业务逻辑", "认证绕过", "账户接管", "水平越权"} {
		if strings.Contains(c, banned) {
			t.Fatalf("导向常量仍内嵌类型词 %q（应迁入热载挖掘方向节）", banned)
		}
	}
	for _, keep := range []string{"触发启发式", "止损线", "响应差异不是漏洞", "挖掘方向"} {
		if !strings.Contains(c, keep) {
			t.Fatalf("导向常量丢失行为纪律关键词 %q", keep)
		}
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
	// 旧版自定义正文缺少目录块时，机器目录仍使用内嵌默认。
	if catalog := srcCatalog(); len(catalog.Entries) == 0 {
		t.Fatal("缺少类型目录块的标准文件未回退默认目录")
	}
	// 不存在的路径 → 回退内嵌默认
	SrcAcceptancePath(dir + "/missing.md")
	if got := srcAcceptance(); !strings.Contains(got, "SRC 漏洞收取标准") {
		t.Fatalf("缺失文件未回退默认: got %q", got)
	}
}
