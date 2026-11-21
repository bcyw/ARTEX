package agent

import (
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// 同类上限闸（票 02）的计数实现：单任务内单一漏洞类型（折叠后规范桶）的
// 有效产出触顶即拒收（addFinding 校验序里排在 severity 之后、SRC 黑名单闸
// 之前——隔离上报不消耗名额，两个闸互不干扰）。
//
// 计数口径：pending + confirmed 为有效产出；quarantined / false_positive /
// duplicate / ignored 不占名额（隔离上报走黑名单闸，发生在本闸之后）。
// 数据源与态势类型分布同源：探索图 finding 节点 payload 的 vulnclass +
// t.ts.ListByKind 预取（零新增 SQL）；探索节点 state 固定 'confirmed'，状态
// 真相在独立 findings 表，经 AssetStore 交叉 FindingMetaByNodeID(taskID)。
//
// ADR-0004 硬约束：代码零漏洞类型词表常量——桶名一律来自 srcFoldVulnClass
// 折叠结果（词表住在热载标准文件里）。

// srcClassCapReached 统计本任务内折叠到 vulnclass 同一规范桶的有效 finding
// 数，并报告是否已达同类上限。返回 (有效数, 上限, 是否触顶)。
// 统计源不可用（ListByKind 失败）时不放闸：拒收必须基于确定的计数，宁放勿误杀；
// 独立状态行缺失的节点按有效计（极罕见的并发窗口/旧数据，上限宁紧勿漏）。
func (t *ToolSet) srcClassCapReached(vulnclass string) (int, int, bool) {
	focus := srcHunting()
	bucket := focus.fold(vulnclass)
	nodes, err := t.ts.ListByKind(db.KindFinding, 1000)
	if err != nil {
		return 0, focus.Cap, false
	}
	var meta map[int64]db.FindingMeta
	if t.as != nil && t.taskID > 0 {
		if m, err := t.as.FindingMetaByNodeID(t.taskID); err == nil {
			meta = m
		}
	}
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
		if m, ok := meta[n.ID]; ok {
			switch m.Status {
			case db.FindingPending, db.FindingConfirmed:
				count++
			}
			continue
		}
		count++
	}
	return count, focus.Cap, count >= focus.Cap
}
