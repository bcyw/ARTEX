package agent

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// 类型目录（type catalog，见 GLOSSARY.md）的机器可查挂载：SRC 收取标准热载
// 文件末尾「机器可查目录」节的 ~~~types 围栏块（票 01：取代原「挖掘方向」节
// 底部的 ~~~hunting 围栏）。
//
// 设计决策（ADR-0004：docs/adr/0004-type-diversity-soft-loop.md）：
//  - 规范类型名清单、别名折叠映射、同类上限三个量全部住在热载文件里（启动
//    读入、免重编译热改口径）；后续票据（同类上限闸、类型分布注入、统计呈现、
//    上报类型归属校验）消费本文件的接口，不各自解析标准文本。
//  - 代码零漏洞类型词表常量：Go 侧只做机械归一（大小写/空白/连字符）+ 查表，
//    规范名、别名、proof/signals/stop 文案一个不进代码。
//  - 折叠绝不拒收：表未覆盖的新写法以归一形自成一桶、照常计数，词表永不堵死
//    合法新类型（反序列化变体、GraphQL 滥用等）。
//  - 不缓存：与 srcAcceptance() 同哲学——本文件按 guidance 组装/上报校验的
//    频率被调用，每次现读现解析的开销可忽略，换来「改文件即生效」的热载语义
//    （重启进程自然生效是验收下限）。
//
// 围栏用 ~~~ 而非 ```：整份标准文本同时内嵌为 Go 原始字符串常量
// srcAcceptanceDefault，其中不能出现反引号。

// srcTypesFence 是机器可查目录围栏标记（严格全词匹配，防止正文误触发）。
const srcTypesFence = "~~~types"

// srcHuntingCapDefault 是机器可查区缺失或损坏时的同类上限回退值（票面默认 3）。
const srcHuntingCapDefault = 3

// srcTypeEntry 是目录里一条类型：规范名 + 是否收取 + 别名 + 证明物/触发/止损。
//   - Name：规范名（书写原形，含空格）。
//   - Collect：true = 可收（受同类上限约束）；false = 明确不收（上报被拒收）。
//   - Aliases：别名 token 清单（每个 token 不带空格，折叠时会抹掉空白/大小写/
//     连字符）。
//   - Proof / Signals / Stop：危害最小证明物 / 触发启发式 / 止损线文案。
//     Proof 与收取标准 §四 证据线同源；Stop 是 collect:no 条目的拒收文案来源。
type srcTypeEntry struct {
	Name    string
	Collect bool
	Aliases []string
	Proof   string
	Signals string
	Stop    string
}

// srcTypeCatalog 是整份目录：按书写序的条目清单 + 全局同类上限。
type srcTypeCatalog struct {
	Entries []srcTypeEntry
	Cap     int
}

// lookup 按归一形（经别名）命中目录条目，返回规范名条目；未命中返回 false。
// 规范名自身与所有别名都参与匹配，语义与 srcHuntingFocus.fold 的折叠一致。
func (c srcTypeCatalog) lookup(name string) (srcTypeEntry, bool) {
	key := srcFoldKey(name)
	for _, e := range c.Entries {
		if srcFoldKey(e.Name) == key {
			return e, true
		}
		for _, a := range e.Aliases {
			if srcFoldKey(a) == key {
				return e, true
			}
		}
	}
	return srcTypeEntry{}, false
}

// fold 把 vulnclass 折叠到目录规范名：归一 → 查表；未命中以归一形自成一桶——
// 照常计数、绝不拒收。语义与 srcHuntingFocus.fold 完全一致。
func (c srcTypeCatalog) fold(vulnclass string) string {
	if e, ok := c.lookup(vulnclass); ok {
		return e.Name
	}
	return srcFoldKey(vulnclass)
}

// srcCatalog 现读现解析当前标准文本（热载文件优先，回退内嵌默认）的类型目录。
// 不缓存：改文件下一次调用即生效；块缺失时仅目录回退内嵌默认，
// 自定义正文保持不变。任何非法行跳过不失败。
func srcCatalog() srcTypeCatalog {
	text := srcAcceptance()
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == srcTypesFence {
			return parseSrcTypes(text)
		}
	}
	return parseSrcTypes(srcAcceptanceDefault)
}

// parseSrcTypes 从标准文本提取第一个 ~~~types 围栏块并构建目录。
// 容错原则：块内无法解析的行（无冒号、空键、非法数字）直接跳过、不失败——
// 标准文件是给人热改的，一次手误不能让整个目录失效；cap 缺省 3、负数忽略、
// 多个合法 cap 行以最后为准；collect 缺省 true，值 no/false/否/不收 视为 false；
// type 行开启一条新条目，后续 collect/aliases/proof/signals/stop 归属当前条目，
// 条目结束（下一个 type 或块收口）时若规范名非空才入清单。
func parseSrcTypes(text string) srcTypeCatalog {
	c := srcTypeCatalog{Cap: srcHuntingCapDefault}
	inBlock := false
	var cur *srcTypeEntry
	flush := func() {
		if cur != nil && cur.Name != "" {
			c.Entries = append(c.Entries, *cur)
		}
		cur = nil
	}
	for _, ln := range strings.Split(text, "\n") {
		line := strings.TrimSpace(ln)
		if !inBlock {
			if line == srcTypesFence {
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
		val = strings.TrimSpace(val)
		switch key {
		case "cap":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				c.Cap = n
			}
		case "type":
			flush()
			if val != "" {
				cur = &srcTypeEntry{Name: val, Collect: true}
			}
		case "collect":
			if cur != nil {
				cur.Collect = parseCollect(val)
			}
		case "aliases":
			if cur != nil {
				cur.Aliases = append(cur.Aliases, strings.Fields(val)...)
			}
		case "proof":
			if cur != nil {
				cur.Proof = val
			}
		case "signals":
			if cur != nil {
				cur.Signals = val
			}
		case "stop":
			if cur != nil {
				cur.Stop = val
			}
		}
	}
	flush()
	return c
}

// parseCollect 解析 collect 开关：缺省 true；no/false/否/不收 视为 false。
func parseCollect(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "false", "否", "不收":
		return false
	}
	return true
}

// srcHuntingFocus 是目录暴露给既有消费方的三个量（票 01 保留，由目录派生）。
//   - Types：全部条目规范名清单，按目录书写序（可收类型在前、不收类型在后）；
//   - Fold：归一后别名 → 规范名的折叠映射（规范名自身也是键）；
//   - Cap：同类上限——单任务内同一规范类型有效产出（pending + confirmed）
//     触发的探索投入上限，触顶停止新增探索（已有独立根因证据仍可登记）。
type srcHuntingFocus struct {
	Types []string
	Fold  map[string]string
	Cap   int
}

// srcHunting 由目录派生旧三量接口（finding_cap / findingTypeCounts 等仍消费）。
// 目录块缺失时由 srcCatalog 回退内嵌默认；未知写法自成一桶照常计数。
func srcHunting() srcHuntingFocus {
	c := srcCatalog()
	f := srcHuntingFocus{Fold: map[string]string{}, Cap: c.Cap}
	for _, e := range c.Entries {
		if !slices.Contains(f.Types, e.Name) {
			f.Types = append(f.Types, e.Name)
		}
		f.Fold[srcFoldKey(e.Name)] = e.Name
		for _, a := range e.Aliases {
			f.Fold[srcFoldKey(a)] = e.Name
		}
	}
	return f
}

// fold 把 vulnclass 折叠到本目录的规范名：归一 → 查表；未命中以归一形
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
