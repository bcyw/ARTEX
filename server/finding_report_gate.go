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

// validateFindingReport 在 update_finding_report 入库前执行交付物骨架校验:
// 缺必需章节或超行数的报告拒绝写入,让 agent 拿到错误后按提示词骨架重写。
// 这是把 report_finding 的 SrcFindingBlocked 式硬闸延伸到最终交付物——
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
	return nil
}
