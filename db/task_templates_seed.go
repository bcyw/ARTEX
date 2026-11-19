package db

import "errors"

// builtinTaskTemplates are the shipped task presets inserted on every startup
// (seedTaskTemplates, wired into seedBuiltins). Insert-if-missing keyed by the
// name's nkey: an existing row — user-edited or not — is never overwritten, and
// a deleted preset is restored on the next start. Same seed policy as the
// browser MCP / skill-visibility seeds.
type builtinTaskTemplate struct {
	Category    string
	Name        string
	Description string
	Goal        string
}

var builtinTaskTemplates = []builtinTaskTemplate{
	{
		Category: "渗透测试",
		Name:     "单域名全量渗透",
		Description: "目标：",
		Goal: "对任务描述中给出的目标开展 SRC 漏洞挖掘，按以下节奏推进：先确认范围并枚举全部存活 Web 入口（含非 80/443 端口、" +
			"JS 文件与页面中引用的接口）；对每个入口摸清功能面（参数、身份体系、业务动作）后逐漏洞类探测；对疑点更换 payload、" +
			"参数变体、不同身份视角做多轮验证；每登记一个可收漏洞后回到未穷尽的入口继续。完成标准是范围内每个存活资产的" +
			"每个可发现接口都测到、主要漏洞面探尽，而非已发现漏洞或已测接口的数量。",
	},
	{
		Category: "渗透测试",
		Name:     "批量资产全量渗透",
		Description: "清单：",
		Goal: "对任务描述中给出的资产清单开展 SRC 漏洞挖掘。清单可能是粘贴文本或文件路径，是路径须先读取文件获得完整清单，" +
			"并把清单内全部目标登记进测试范围。先做存活确认与价值分层，优先测试高价值目标（有登录、支付、API、管理面或敏感业务的资产）。" +
			"挖掘节奏：枚举每个存活资产的全部 Web 入口（含非 80/443 端口、JS 中引用的接口）；对每个入口摸清功能面后逐漏洞类探测；" +
			"对疑点更换 payload、参数变体、不同身份视角做多轮验证；每登记一个可收漏洞后回到未穷尽的入口继续。" +
			"完成标准是清单内每个存活资产的每个可发现接口都测到、主要漏洞面探尽，而非已发现漏洞或已测资产的数量。",
	},
	{
		Category: "资产梳理",
		Name:     "资产梳理",
		Description: "清单：",
		Goal: "对任务描述中给出的资产清单完成资产梳理与攻击面测绘。清单可能是粘贴文本或文件路径，是路径须先读取文件获得完整清单。" +
			"逐项确认存活状态；对每个存活资产做指纹识别与技术栈归类；发现的 Web 入口、端口服务、管理后台、API 接口、" +
			"登录入口全部登记进资产图，作为后续渗透任务的输入。完成标准是清单内每一项都处理完毕，禁止抽查式收敛。" +
			"本任务只做测绘，不做漏洞利用。",
	},
}

// seedTaskTemplates inserts the shipped task presets and their categories,
// skipping anything whose name already exists (user-owned from then on).
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
		if _, err := d.CreateTaskTemplate(TaskTemplateInput{
			Name:        tmpl.Name,
			Description: tmpl.Description,
			Goal:        tmpl.Goal,
			CategoryID:  &categoryID,
		}); err != nil && !errors.Is(err, ErrTaskTemplateNameConflict) {
			return err
		}
	}
	return nil
}
