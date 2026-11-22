package agent

import (
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// 同类上限闸（票 02）的计数实现：单任务内单一漏洞类型（折叠后规范桶）的
// 有效产出触顶即拒收（addFinding 校验序里排在 severity 之后、类型归属校验
// 之后——归属校验通过的类型才参与计数，两闸互不干扰）。
//
// 计数口径：pending + confirmed 为有效产出；quarantined / false_positive /
// duplicate / ignored 不占名额（quarantined 是旧版词表闸的历史状态，新代码
// 不再产生，仅保留存量数据的交叉口径）。
// 数据源与态势类型分布同源：探索图 finding 节点 payload 的 vulnclass +
// t.ts.ListByKind 预取（零新增 SQL）；探索节点 state 固定 'confirmed'，状态
// 真相在独立 findings 表，经 AssetStore 交叉 FindingMetaByNodeID(taskID)。
//
// ADR-0004 硬约束：代码零漏洞类型词表常量——桶名一律来自 srcFoldVulnClass
// 折叠结果（词表住在热载标准文件里）。

// srcClassCapReached 统计本任务内折叠到 vulnclass 同一规范桶的有效 finding
// 数，并报告是否已达同类上限。返回 (有效数, 上限, 是否触顶)。计数经
// findingStatusMeta 交叉 findings 表状态（与态势类型分布共享同一口径实现）。
// 统计源不可用（ListByKind 失败）时不放闸：拒收必须基于确定的计数，宁放勿误杀；
// 状态真相不可交叉（AssetStore 缺席或查询失败）时回退到节点态
// （confirmed 计入、dismissed 排除），与 findingTypeCounts 共享口径。
func (t *ToolSet) srcClassCapReached(vulnclass string) (int, int, bool) {
	focus := srcHunting()
	bucket := focus.fold(vulnclass)
	nodes, err := t.ts.ListByKind(db.KindFinding, 1000)
	if err != nil {
		return 0, focus.Cap, false
	}
	meta := t.findingStatusMeta()
	count := 0
	for _, n := range nodes {
		var fp map[string]any
		if json.Unmarshal(n.Payload, &fp) != nil {
			continue
		}
		vc, _ := fp["vulnclass"].(string)
		if focus.fold(vc) != bucket {
			continue
		}
		status := n.State
		if m, ok := meta[n.ID]; ok {
			status = m.Status
		}
		if findingStatusExcluded(status) {
			continue
		}
		count++
	}
	return count, focus.Cap, count >= focus.Cap
}
