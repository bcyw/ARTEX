package db

import "errors"

// builtinTaskTemplates are seeded by name's nkey on startup. Only exact legacy
// defaults are upgraded; user edits are preserved. Deleted presets are restored.
type builtinTaskTemplate struct {
	Category    string
	Name        string
	Description string
	Goal        string
}

// Shared by the two hunting presets so their evidence and stopping criteria agree.
// The runtime SRC standards remain authoritative for types, proof and limits.
const srcHuntingTaskGoal = `

挖掘策略：
1. 以可提交 SRC 的中危、高危、严重漏洞为目标，优先选择“真实入口 + 可控输入或明确组件线索 + 可验证危害”的技术利用路线。先理解业务功能、身份边界、数据流与关键操作，再围绕具体假设验证；不把接口数量、扫描告警数量或逐类打卡当作产出。
2. 主攻有证据支持的组件已知漏洞、反序列化、模板/表达式注入、SQL/NoSQL 注入、命令执行、SSRF、文件处理及其升级链。重点梳理导入导出、文件预览/转换、上传下载、URL 抓取、搜索查询、工作流与管理接口；指纹与版本只是线索，须确认可达入口及利用前置条件，不凭技术栈猜测盲测。
3. 同时关注核心账户接管、敏感数据访问及支付/订单等关键业务状态的实际影响。普通未授权、越权、泄露线索优先作为链路入口；只有存在明确危害假设才继续，避免停留在普通访问差异。需要身份对照时使用任务提供的测试账号，缺少账号或其他前置条件则记录受阻原因并转向可验证路线。
4. 每条路线明确入口、机制、组件/参数、前置条件、预期危害及最小证明物。从当前 SRC 类型目录的可收类型建立验证意图，按标准卡取证；机制不等于漏洞结果，同一类型仍可能有不同技术利用路线。出现升级证据时交由规划者建立对应意图，执行者不临时换类型。
5. 验证包含正常请求基线、否定对照、实际影响证据及复现步骤；用最小、非破坏性的证明物确认影响，避免为定级扩大数据读取或业务变更。状态码、报错、版本、单次时间差及带外回调仅是线索；带外证据须关联具体探测，继续确认实际危害，服务不可用不等于路线阴性。
6. 按“可收性 × 危害 × 证据”动态排序。有新事实或未验证的关键变体才继续同路线；前置条件证伪、有效阴性、变体耗尽或达到运行时路线/同类/任务预算即停止，记录原因并换向。发现一条漏洞后补强证据、查重，再处理下一条高价值路线，不靠换参数名称或换摘要重复派发。
7. 已证实漏洞按当前 SRC 收取标准如实定级，不因任务目标预设为高危；中危结果达到证据线同样保留。发现与事实分开记录：缺少危害证明的线索记事实，低价值信息不作为挖掘成果凑数。提交稿按报告骨架写清前置条件、raw 请求、实际响应、复现步骤与已证明的影响；有流量证据快照时绑定对应证据。

完成标准：高价值候选路线均有已证实、有效阴性、前置条件缺失或预算止损等可追溯结论，重要入口没有未经解释的遗漏。任务工作记录列出剩余线索、受阻原因与继续验证所需条件；交付报告只收已确认漏洞。不以“必须挖到严重漏洞”或“所有接口所有类型穷尽”作为结束条件。`

var builtinTaskTemplates = []builtinTaskTemplate{
	{
		Category:    "渗透测试",
		Name:        "单域名全量渗透",
		Description: "目标：",
		Goal: `对任务描述给出的单域名开展 SRC 深度挖掘，优先取得中危、高危、严重漏洞的可复现证据。
先读取目标范围、已知业务入口、测试账号及补充约束；围绕范围内目标发现存活 Web 入口、非标准端口、页面与 JS 引用的接口，并登记资产及来源。关联域名和第三方服务先确认是否在任务范围内，再纳入测试。
建立业务功能与技术利用路线清单，优先深入存在危险输入、复杂文件处理、服务端调用或高价值业务操作的入口；侦察为验证具体假设服务，避免持续扩面挤占深挖预算。` + srcHuntingTaskGoal,
	},
	{
		Category:    "渗透测试",
		Name:        "批量资产全量渗透",
		Description: "清单：",
		Goal: `对任务描述给出的资产清单开展 SRC 高价值漏洞挖掘，优先取得中危、高危、严重漏洞的可复现证据。清单为文件路径时先读取完整文件；全部条目登记、去重并标记范围、存活状态和来源，不以抽样代替清单处理。
先做轻量测绘，按实际功能、技术栈、身份边界与已有线索分层：优先存在可控危险输入、明确组件利用前置条件、核心身份/敏感数据/支付业务的资产；仅静态内容或低信息量入口降低优先级，线索变化后重新排序。
同构资产按组件与功能分组，先验证线索最强的代表入口；有效路线再对范围内同源入口确认适用条件和影响范围，避免机械重复扫描。同构不代表全部受影响或全部安全；保留各资产的实测状态，独立部署差异单独验证，同根因产出合并补证。` + srcHuntingTaskGoal,
	},
	{
		Category:    "资产梳理",
		Name:        "资产梳理",
		Description: "清单：",
		Goal: `为后续 SRC 中危、高危、严重漏洞挖掘建立可执行的攻击面清单。本任务只做资产梳理与攻击面测绘，不做漏洞利用。
1. 清单为文件路径时先读取完整内容；逐项登记、去重，记录来源、范围及存活状态。无法访问的条目区分解析失败、网络受阻、需要身份等原因，不能直接标记安全；关联资产先核实范围。
2. 梳理存活资产的 Web 入口、非标准端口、组件/技术栈、登录与管理入口、页面及 JS 引用的 API。记录实际可见的业务功能、参数形态、身份要求和响应证据，版本指纹标明确定程度。
3. 优先标注文件上传下载、导入导出、预览转换、URL 抓取、搜索查询、工作流、身份认证及支付/订单等关键入口；为候选技术利用路线写出入口、机制假设、支持证据、待确认的前置条件及下一步验证建议。未验证线索记事实，不写成已成立漏洞。
4. 按业务影响、危险输入与证据强度给出后续验证优先级及理由；同构系统分组并保留各自状态，标明缺少的账号、业务上下文或访问条件。
完成标准：清单内每一项都有处理状态，已发现入口及其来源进入资产图，高价值候选具备可接续的验证建议，遗漏和受阻项有明确说明。仅有域名、端口、指纹数量不算完成。`,
	},
}

// Exact pre-SRC-focus snapshots for upgrading untouched installations. Keep these
// immutable: comparing the whole default prevents clobbering user customization.
var legacyTaskTemplateGoals = map[string]string{
	"单域名全量渗透": "对任务描述中给出的目标开展 SRC 漏洞挖掘，按以下节奏推进：先确认范围并枚举全部存活 Web 入口（含非 80/443 端口、" +
		"JS 文件与页面中引用的接口）；对每个入口摸清功能面（参数、身份体系、业务动作）后逐漏洞类探测；对疑点更换 payload、" +
		"参数变体、不同身份视角做多轮验证；每登记一个可收漏洞后回到未穷尽的入口继续。完成标准是范围内每个存活资产的" +
		"每个可发现接口都测到、主要漏洞面探尽，而非已发现漏洞或已测接口的数量。",
	"批量资产全量渗透": "对任务描述中给出的资产清单开展 SRC 漏洞挖掘。清单可能是粘贴文本或文件路径，是路径须先读取文件获得完整清单，" +
		"并把清单内全部目标登记进测试范围。先做存活确认与价值分层，优先测试高价值目标（有登录、支付、API、管理面或敏感业务的资产）。" +
		"挖掘节奏：枚举每个存活资产的全部 Web 入口（含非 80/443 端口、JS 中引用的接口）；对每个入口摸清功能面后逐漏洞类探测；" +
		"对疑点更换 payload、参数变体、不同身份视角做多轮验证；每登记一个可收漏洞后回到未穷尽的入口继续。" +
		"完成标准是清单内每个存活资产的每个可发现接口都测到、主要漏洞面探尽，而非已发现漏洞或已测资产的数量。",
	"资产梳理": "对任务描述中给出的资产清单完成资产梳理与攻击面测绘。清单可能是粘贴文本或文件路径，是路径须先读取文件获得完整清单。" +
		"逐项确认存活状态；对每个存活资产做指纹识别与技术栈归类；发现的 Web 入口、端口服务、管理后台、API 接口、" +
		"登录入口全部登记进资产图，作为后续渗透任务的输入。完成标准是清单内每一项都处理完毕，禁止抽查式收敛。" +
		"本任务只做测绘，不做漏洞利用。",
}

// seedTaskTemplates inserts the shipped task presets and their categories,
// upgrading exact legacy defaults and preserving customized rows.
func (d *DB) seedTaskTemplates() error {
	categoryIDs := make(map[string]int64)
	for _, tmpl := range builtinTaskTemplates {
		if _, ok := categoryIDs[tmpl.Category]; ok {
			continue
		}
		category, err := d.CreateTaskCategory(tmpl.Category)
		switch {
		case err == nil:
			categoryIDs[tmpl.Category] = category.ID
		case errors.Is(err, ErrTaskCategoryNameConflict):
			categories, listErr := d.ListTaskCategories()
			if listErr != nil {
				return listErr
			}
			for _, existing := range categories {
				if existing.Name == tmpl.Category {
					categoryIDs[tmpl.Category] = existing.ID
					break
				}
			}
			if _, ok := categoryIDs[tmpl.Category]; !ok {
				return errors.Join(err, ErrTaskCategoryNotFound)
			}
		default:
			return err
		}
	}
	for _, tmpl := range builtinTaskTemplates {
		categoryID := categoryIDs[tmpl.Category]
		_, err := d.CreateTaskTemplate(TaskTemplateInput{
			Name:        tmpl.Name,
			Description: tmpl.Description,
			Goal:        tmpl.Goal,
			CategoryID:  &categoryID,
		})
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrTaskTemplateNameConflict) {
			return err
		}
		if previous, ok := legacyTaskTemplateGoals[tmpl.Name]; ok {
			// Compare and update atomically, including description and category so
			// an otherwise unchanged template customized for a target stays intact.
			if _, err := d.Exec(`UPDATE task_templates SET goal=$1, updated_at=now()
WHERE nkey=$2 AND name=$3 AND description=$4 AND goal=$5 AND category_id=$6`,
				tmpl.Goal, taskTemplateNKey(tmpl.Name), tmpl.Name, tmpl.Description, previous, categoryID); err != nil {
				return err
			}
		}
	}
	return nil
}
