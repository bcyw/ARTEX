package agent

import (
	"strconv"
	"strings"
	"unicode"
)

// 挖掘方向（hunting focus，见 GLOSSARY.md）的机器可查挂载：SRC 收取标准热载
// 文件「挖掘方向」节底部的 ~~~hunting 围栏块。
//
// 设计决策（ADR-0004：docs/adr/0004-type-diversity-soft-loop.md）：
//  - 规范类型名清单、别名折叠映射、同类上限三个量全部住在热载文件里（启动
//    读入、免重编译热改口径）；后续票据（同类上限闸、类型分布注入、统计呈现）
//    消费本文件的接口，不各自解析标准文本。
//  - 代码零漏洞类型词表常量：Go 侧只做机械归一（大小写/空白/连字符）+ 查表，
//    桶名与别名一个不进代码。
//  - 折叠绝不拒收：表未覆盖的新写法以归一形自成一桶、照常计数，词表永不堵死
//    合法新类型（反序列化变体、GraphQL 滥用等）。
//  - 不缓存：与 srcAcceptance() 同哲学——本文件按 guidance 组装/上报校验的
//    频率被调用，每次现读现解析的开销可忽略，换来「改文件即生效」的热载语义
//    （重启进程自然生效是验收下限）。
//
// 围栏用 ~~~ 而非 ```：整份标准文本同时内嵌为 Go 原始字符串常量
// srcAcceptanceDefault，其中不能出现反引号。

// srcHuntingFence 是机器可查区围栏标记（严格全词匹配，防止正文误触发）。
const srcHuntingFence = "~~~hunting"

// srcHuntingCapDefault 是机器可查区缺失或损坏时的同类上限回退值（票面默认 3）。
const srcHuntingCapDefault = 3

// srcHuntingFocus 是挖掘方向节暴露的三个量。
//   - Types：规范类型名清单，按文件书写序即优先级序（七类在前、越权垫底）；
//   - Fold：归一后别名 → 规范桶名的折叠映射（规范桶名自身也是键）；
//   - Cap：同类上限——单任务内同一规范类型有效产出（pending + confirmed）
//     的数量上限，触顶即拒收该类型新 finding（见热载节文案）。
type srcHuntingFocus struct {
	Types []string
	Fold  map[string]string
	Cap   int
}

// srcHunting 解析当前标准文本（热载文件优先，回退内嵌默认）的机器可查区。
// 区缺失时返回零词表 + 默认上限：一切写法自成一桶照常计数、绝不拒收，上限
// 仍按默认值生效——词表缺失不构成放水或堵死的理由。
func srcHunting() srcHuntingFocus {
	return parseSrcHunting(srcAcceptance())
}

// parseSrcHunting 从标准文本中提取第一个 ~~~hunting 围栏块并构建三个量。
// 容错原则：块内无法解析的行（无冒号、空键、非法数字）直接跳过、不失败——
// 标准文件是给人热改的，一次手误不能让折叠机制整体失效；多个合法 cap 行以
// 最后为准；负数 cap 视为手误忽略（0 是合法的显式配置，照收）。
func parseSrcHunting(text string) srcHuntingFocus {
	f := srcHuntingFocus{Fold: map[string]string{}, Cap: srcHuntingCapDefault}
	inBlock := false
	for _, ln := range strings.Split(text, "\n") {
		line := strings.TrimSpace(ln)
		if !inBlock {
			if line == srcHuntingFence {
				inBlock = true
			}
			continue
		}
		if strings.HasPrefix(line, "~~~") { // 收口围栏（任意波浪线围栏）
			break
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if key == "cap" {
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil && n >= 0 {
				f.Cap = n
			}
			continue
		}
		// 规范桶行：桶名自身与各别名都以归一形入表、指向桶名原文；重复出现的
		// 桶名只入清单一次（别名合并，后行覆盖同键）。
		if !containsString(f.Types, key) {
			f.Types = append(f.Types, key)
		}
		f.Fold[srcFoldKey(key)] = key
		for _, alias := range strings.Fields(val) {
			f.Fold[srcFoldKey(alias)] = key
		}
	}
	return f
}

// fold 把 vulnclass 折叠到本词表的规范桶名：归一 → 查表；未命中以归一形
// 自成一桶——照常计数、绝不拒收。
func (f srcHuntingFocus) fold(vulnclass string) string {
	key := srcFoldKey(vulnclass)
	if bucket, ok := f.Fold[key]; ok {
		return bucket
	}
	return key
}

// srcFoldVulnClass 单发便捷入口：按当前标准文本折叠任意 vulnclass 写法。
// 例：sql_injection / SQL 注入 / SQLi → 注入类；GraphQL 滥用 → 自成桶。
func srcFoldVulnClass(vulnclass string) string {
	return srcHunting().fold(vulnclass)
}

// SrcFoldVulnClass 把任一 vulnclass 写法折叠到规范桶名，供包外消费（票 05：
// server 呈现层按规范桶合并类型分布；db 包不 import agent，折叠只在呈现层做）。
// 未覆盖的写法以归一形自成一桶、绝不拒收——语义同 srcFoldVulnClass。
func SrcFoldVulnClass(vulnclass string) string {
	return srcFoldVulnClass(vulnclass)
}

// srcFoldKey 是 vulnclass 的机械归一：小写、去空白与 - / _ 分隔符。
// 「SQL 注入」「sql-injection」「Sql_Injection」归一为同键；归一只做机械
// 变形、不含任何词表——类型词表住在热载文件里（ADR-0004 硬约束）。
func srcFoldKey(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '_':
			return -1
		}
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// containsString 报告切片是否含指定字符串。
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
