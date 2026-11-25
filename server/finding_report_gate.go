package server

import (
	"fmt"
	"strings"
)

// findingReportRequiredHeadings 是 update_finding_report 入库硬校验的必需章节,
// 必须与 reporter 系统提示词(agent/promptcatalog.go ReporterDefaultPrompt)的十节
// 骨架保持一致。只列无条件必需的四节;测试账号节按提示词规则允许整节省略。
// 改这里时同步改 ReporterDefaultPrompt 与 update_finding_report 的工具描述。
var findingReportRequiredHeadings = []string{
	"## 漏洞名称",
	"## 漏洞复现步骤（POC）",
	"## 漏洞危害",
	"## 修复建议",
}

// findingReportMaxLines 是报告的硬性行数上限,防整段倾倒报文/日志原文。
// 注意实测合规报告约 140 行,上限须留足余量,不是"建议行数"的翻倍即所得。
const findingReportMaxLines = 300

// findingReportBannedPhrases 是提交稿正文的内部词汇黑名单:报告是交付给外部的
// 正式漏洞报告,不得出现内部工具名、worker 名、系统字段或过程元数据。命中即拒绝
// 入库,错误消息要求改写成面向读者的自然语言。只列不会在正常技术叙述中出现的
// 内部专名,避免误杀正常词汇(如"版本"单独出现是正常的)。
var findingReportBannedPhrases = []string{
	// 内部 agent/工具专名
	"get_finding_traffic",
	"get_task_node_detail",
	"update_finding_report",
	"report_finding",
	"bind_finding_traffic",
	"traffic_search",
	"traffic_get",
	"worker#",
	"work#",
	// 过程元数据字段(以带值/带冒号的形式出现才有意义,但直接禁词更稳)
	"bindings",
	"evidence_version",
	"report_evidence_version",
	"finding_node_id",
	"exploration_nodes",
}

// validateFindingReport 在 update_finding_report 入库前执行交付物骨架校验:
// 缺必需章节、超行数或正文含内部词汇的报告拒绝写入,让 agent 拿到错误后按提示词
// 骨架重写。这是把 report_finding 的 SrcFindingBlocked 式硬闸延伸到最终交付物——
// 报告结构不依赖模型服从性,由系统保证。
func validateFindingReport(report string) error {
	if strings.Count(report, "\n")+1 > findingReportMaxLines {
		return fmt.Errorf("报告超过 %d 行上限,请精简:证据细节由关联流量与关键片段承载,不整段倾倒报文原文,修正后重新提交", findingReportMaxLines)
	}
	present := map[string]bool{}
	for _, line := range strings.Split(report, "\n") {
		present[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, h := range findingReportRequiredHeadings {
		if !present[h] {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("报告骨架校验失败:缺少必需章节 %s。报告结构必须严格按你系统提示词中的十节骨架撰写(上述标题行逐字使用,独立成行),补齐后重新提交", strings.Join(missing, "、"))
	}
	var banned []string
	for _, p := range findingReportBannedPhrases {
		if strings.Contains(report, p) {
			banned = append(banned, p)
		}
	}
	if len(banned) > 0 {
		return fmt.Errorf("报告正文含内部系统词汇 %s。报告是交付给外部的正式文档,不得出现内部工具名、worker 名、系统字段或缺失材料的过程说明。请直接保留已有 PoC、命令与实际输出；raw 请求/响应只使用已绑定的证据快照，不拼造报文。材料不足时在工作记录说明缺口，不用占位语覆盖已有稿件；修正后重新提交", strings.Join(banned, "、"))
	}
	return nil
}
