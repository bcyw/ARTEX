package agent

import (
	"os"
	"strings"
	"sync"
)

// SRC 漏洞收取标准（standards/src-acceptance.md）的运行时挂载。
//
// 设计决策（与用户确认过）：
//  - 标准以【代码固定注入段】的形式拼进 guidance（findingWorkflowTools 返回值 →
//    deferredSystem 拼进系统提示），而 NOT 改各 agent 的 DB 可编辑模板 —— 这样
//    用户在 UI 里改过的提示词不会被覆盖，质量纪律也永远不会被编辑掉（Q10-C）。
//  - 黑名单在 addFinding() 做入库硬闸：声明字段（vulnclass/name/summary）命中
//    且无升级证据的照常入库但 status='quarantined'（隔离区，可在页面人工
//    检查/放行），不进交付报告（报告只取 confirmed）。
//  - 标准正文可被仓库外文件覆盖：SrcAcceptancePath 指向的文件存在则优先读它，
//    方便按不同 SRC 平台换口径而无需重新编译。
//
// 硬闸匹配范围（见 SrcFindingBlocked 注释）：类型判定只看声明字段，evidence/
// description 里的上下文性提及（如「已排除点击劫持」）不参与，防止误杀合法漏洞。

// srcAcceptanceDefault 内嵌默认标准（与 standards/src-acceptance.md 同步维护）。
// 保留在代码里的原因：go run / 单测 / 未随包分发 standards 目录的场景下仍然生效。
const srcAcceptanceDefault = `**SRC 漏洞收取标准（宁缺毋滥——最高优先级纪律）**：
只报告有真实危害、SRC 平台可直接收取的漏洞。无把握一律 record_fact 记 inferred 事实，不报 finding。每条 finding 必须有「完整利用步骤 + 实际响应证据」；理论可利用（仅 dnslog 回连/仅可爆破/仅报错）、前置条件无法满足的一律不报。

**公开性检查（每条 finding 上报前必过——回答：这是不是"符合业务预期的产品设计"？）**：
以未登录/无凭据会话判定，任一命中即设计如此，作废记 fact：
1. 内容公开性：数据本来就无鉴权公开可达且无叠加攻击面（用户名/邮箱/公开 UUID/robots.txt/版本 banner/报错串 = 公开信息，不构成漏洞）。
2. 意图公开性：行为见于官方文档/正常业务流程，或入口本就面向公众（公开主页/分享页/排行榜/公开 API）。判定看危害是否为 0，不是"看起来奇怪"。
密钥例外：真实密钥/凭据泄露不受公开性豁免（公开性只豁免无危害信息，不豁免可利用凭据）。
完成判据：找到未登录可见的正常前端入口拿到同样数据 → 作废；找不到入口且同域基线接口确实拒绝匿名 → 通过。

**黑名单（默认禁止挖掘/上报；命中且无升级证据的，强行上报会被系统拦截进隔离区）**：
1. Self-XSS、无敏感操作的反射 XSS——升级条件：反射点位于鉴权/支付/个人资料等敏感页面上下文
2. 低危 CSRF（改资料类）——升级条件：可触达改绑手机/邮箱、资金、管理等敏感操作
3. JSONP 劫持、CRLF 无利用面——升级条件：能实际带出敏感数据/完成可演示危害
4. 信息泄露（报错/目录列表/.git/备份）无进一步利用——升级条件：从泄露内容实际还原出可利用物（源码→注入点/凭据）
5. 弱口令/默认口令——升级条件：高权账户或可横向影响
6. 理论 IDOR 无数据证明——升级条件：展示了他人真实数据记录
7. 未授权接口但返回无敏感数据——升级条件：返回字段含手机号/订单/身份等业务敏感数据，且非公开页面数据源（过公开性检查）
8. 端口/指纹/版本披露——一票否决，无升级条件
9. 点击劫持、iframe 嵌套——一票否决，无升级条件
10. 无回显/无利用链 SSRF——升级条件：拿到内网实际响应内容并可进一步操作
11. 用户名枚举/账号存在性泄露（响应差异 oracle）——升级条件：从枚举实际走到接管（撞库成功登录他人账号）或批量泄露用户清单本身即敏感数据

**危害最小证明物（按类型——拿不出证明物 = 不成立，报了也会被平台驳回）**：
- SQL/NoSQL/SSTI/XXE 注入：**注出一条真实数据**（最低共识 = 注出库名 database()；盲注需时间差+库名内容）；仅报错关键词/报错差异不算。
- 越权/IDOR：**A/B 交叉证明**（A 的资源 B 的 token 能读/改，B 返回非空且等于 owner 视图内容）**+ 公开性检查通过**（该数据在正常前端无未登录可见路径）；只读到自己、B 返回 []/null ≠ 被拦不算。
- 数据泄露：**他人的数据 + ≥3 个敏感字段 + 非公开/非样例 + 公开性检查通过**；自己测试账号的数据 ≠ 漏洞。
- SSRF：服务端发出（回调 UA 证明）+ **必须回显内网数据**（云元数据/内网 banner/内网页面）；仅 DNSlog 出网 = 理论可行不收。
- 认证绕过/接管：**任意**用户可绕过，不只证明自己能登自己号；OAuth/JWT/密码重置要 A/B 双账号证明。
- RCE/命令执行：真实命令执行实证——能执行命令本身就是危害。
- 业务逻辑/资金：操作**真实生效**且影响**他人**业务状态（金额/订单/状态机），自己测试数据不算。
- 文件上传：webshell 可执行或存储型 XSS 真实触发；只传上去纯存储不解析 = 不成立。
- **不成报清单**：用户名枚举/账号存在性泄露（属中间信号，需结合爆破才转化为危害）、CORS、安全头缺失、Cookie 标志位、单纯密钥/token 泄露（只作高危链证据不单独成报）。

**硬门（所有漏洞必过，缺一不报）**：
1. **先证伪**：假设"这是正常功能"，主动跑否定实验，三类：不存在的值跑同协议排除 catch-all、合法 body 重测排除假阳性、**公开性检查**排除设计如此；任何一类证伪掉 = 作废不报。
2. **PoC 可复现**：原始请求块直接粘贴可重放，不需额外上下文。
3. **危害是链路终局**：数据泄露/账户接管/资金损失/RCE/内网横向的**终局结果**，不是中间信号（枚举出用户名、拿到 token、摸清拓扑都不是终点）。
4. **服务端/权限边界确认**：不是浏览器 JS 假象/调试功能/页面渲染。

**查重（上报前必查）**：同一资产 + 同一根因 + 同一接口 + 同一影响面 = 同一漏洞，补强已有 finding，不新写；先查探索图与已有 findings 再上报。

**定级纪律**：定级锚 SRC 平台体系（严重/高/中/低），不写 CVSS 分数；无 exploit 评分封顶【中】。critical=RCE/拖库/直接获取大量真实用户数据/核心账户接管；high=存储 XSS/越权批量数据访问/支付逻辑漏洞；medium=单用户越权/反射 XSS（升级后）/多条件串联泄露；low=前三类都不适用但确有真实危害。拿不准降级不升级，实在拿不准记 fact 交人工判断。

**复测纪律**：复测结论 reproduced 才算有效佐证；连续 2 次复测无法复现 → 标记 false_positive。traffic_refs 中已含完整利用响应（proof 角色）的，视为已具备完整利用证据。报告必须附验证证据（原始请求/响应原文，经 traffic 绑定）——平台对 AI 生成且无验证证据的报告直接驳回。`

var (
	srcAcceptanceMu   sync.RWMutex
	srcAcceptancePath string // 测试可覆盖；生产由 server 设置为 <repo>/standards/src-acceptance.md
)

// SrcAcceptancePath sets the on-disk override for the SRC acceptance standard.
// An empty/unset path or an unreadable file falls back to the in-code default.
func SrcAcceptancePath(p string) {
	srcAcceptanceMu.Lock()
	defer srcAcceptanceMu.Unlock()
	srcAcceptancePath = p
}

// srcAcceptance returns the current standard text. Read-through cache would be
// premature: this runs once per agent assembly (not per tool call), and a fresh
// read each time means editing the file takes effect on the next run.
func srcAcceptance() string {
	srcAcceptanceMu.RLock()
	p := srcAcceptancePath
	srcAcceptanceMu.RUnlock()
	if p == "" {
		return srcAcceptanceDefault
	}
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return srcAcceptanceDefault
}

// srcQuarantineNote 是 guidance 里对硬闸行为的说明：黑名单命中会被拦截进隔离区，
// 提前告知可以减少 agent 硬闯被拒后的重试空转。
const srcQuarantineNote = "\n\n黑名单命中且无升级证据的上报会被系统拦截进隔离区（quarantined，可在页面人工检查/放行）。这不是「写对暗号就能过」的关卡：拿不出对应的升级证据就说明该方向当前不成立，改记 inferred 事实并转其他方向，不要为放行而包装措辞。"

// srcHighRiskHunting 是中高危漏洞挖掘导向（常驻注入，与收取标准同文件——同为
// 「产出什么漏洞」的纪律，单一事实源）。设计要点：
//   - 覆盖 SRC 中高危的【全部主要类别】，不限于用户举例的 5 类；
//   - 只放「优先级 + 触发启发式」这一层（每轮都在上下文，控制篇幅）；
//   - 深度方法论（载荷递进/绕过清单/gadget 链）不在这里——那是模型自身的能力，
//     写出来是 no-op，只占上下文。
const srcHighRiskHunting = `

**中高危挖掘导向（优先级高于广度铺面，但与收取标准同级纪律——报不出来的深挖是浪费）**：SRC 收取的主要是中高危，以下类别按「可收性×危害」优先投入，发现候选点时优先深挖到实际危害再转其他方向：
- **注入类**：SQL 注入（union/报错/布尔/时间盲，注意 JSON 参数、排序字段、in 子句、二次注入）、NoSQL/ORM 注入、模板注入（SSTI，{{7*7}}/${7*7} 类探测，注意 Velocity/Freemarker/Thymeleaf/Jinja2/Twig 特征）、表达式注入（SpEL/OGNL/EL）、XPath 注入。
- **执行类**：命令执行/代码执行（RCE，注意系统命令拼接、eval 类、定时任务/工作流节点）、反序列化（Java：Fastjson/Jackson/Shiro/ Commons-Collections gadget；Python：pickle；PHP：phar/serialize；.NET：ViewState/ObjectStateFormatter——发现序列化数据特征即优先验证）、文件上传绕过（解析漏洞/双后缀/竞态/.htaccess）。
- **SSRF**：所有接受 URL/域名/IP 的参数（webhook、图片/文件抓取、导入、代理、预览、回调地址），探测内网 + 协议（file/gopher/dict），拿到内网响应或链式利用才算。
- **认证与越权**：水平/垂直越权（改 id/遍历，展示他人真实数据）、JWT/session 伪造、密码重置/验证码逻辑缺陷（可接管任意账户）、未授权访问敏感数据接口。
- **业务逻辑**：支付金额/数量篡改、负数/并发竞态（余额/积分/优惠券）、短信轰炸、批量注册、越权操作他人资源。
- **文件包含/读取**：LFI→RCE 链（日志注入/协议封装）、任意文件读取（配置/源码→凭据→二次利用）。
**触发启发式**：参数值出现回显/报错差异、响应时间可操控、返回内容随输入结构变化、看到序列化/模板/表达式语法被解析、URL 参数触发服务端外连——任一命中即把该方向升级为深挖路线，穷尽该类手段再收手。
**止损线（与深挖同等重要）**：深挖的前提始终是「该数据/接口过得了公开性检查」——候选点先问"未登录在正常前端是否也拿得到同样数据"，拿得到就立刻降级为普通探索事实、不再投入；打了 3 轮同类探测仍无危害最小证明物进展（无新回显/无新数据/无新边界变化）即收手转其他方向，不与单一参数死磕。`

// findingGuidanceWithStandards wraps the workflow guidance with the SRC
// acceptance standard. Only agents that can actually produce findings
// (report_finding) get the full discipline; read-only roles are untouched.
func findingGuidanceWithStandards(guidance string) string {
	return guidance + "\n\n" + srcAcceptance() + srcQuarantineNote + srcHighRiskHunting
}

// --- 黑名单匹配（addFinding 硬闸用） ---

// srcFlat 把文本压成关键词匹配用的连写形：小写、去掉空白与 _ - 分隔符。
// 「username_enumeration」「reflected-xss」「反射 XSS」与自然语言写法同形匹配，
// 字段之间由调用方拼 \x00 分隔防止跨字段误拼出关键词。
func srcFlat(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '_', '-':
			return -1
		}
		return r
	}, strings.ToLower(s))
}

// srcHardVetoVulnClasses 是无升级条件的一票否决类（标准 #8/#9：端口/指纹/
// 版本披露、点击劫持）——写再多「升级证据」也不放行。
var srcHardVetoVulnClasses = []string{
	"version_disclosure", "fingerprint", "port_scan", "port_disclosure",
	"clickjacking", "iframe_clickjacking",
}

// srcHardVetoKeywords 与上表对应的中文关键词（只收不会误伤合法漏洞的词形：
// 「会话劫持」是合法高危，裸「劫持」会误杀，故只收「点击劫持」全词）。
var srcHardVetoKeywords = []string{"点击劫持", "端口扫描", "版本披露", "指纹识别", "指纹泄露"}

// srcBlacklistVulnClasses 是按 vulnclass 精确匹配（不区分大小写，空格归一为
// 下划线）的普通黑名单类（带升级条件，写明「升级证据」可放行）。只收连写形
// 不会被关键词表覆盖的英文类名；JSONP/CRLF/Self-XSS/CSRF/反射 XSS/用户名枚举
// 等由关键词表覆盖（vulnclass 文本会拼进声明字段参与关键词匹配）。
var srcBlacklistVulnClasses = []string{
	// #5 弱口令/默认口令
	"weak_password", "default_credential", "default_password", "weak_credential",
	// #3 CRLF 的类名变体（「crlf」走关键词）
	"header_injection",
	// #1 反射 XSS 的类名变体（reflected_xss 走关键词）
	"xss_reflected", "reflect_xss",
	// #2 CSRF（低危改资料类；触达改绑/资金/管理需写明升级证据）
	"csrf",
	// #4 信息泄露（报错/目录列表/.git/备份）无进一步利用
	"directory_listing", "git_exposure", "git_leak", "backup_exposure", "backup_leak",
	"source_leak", "source_code_leak", "debug_info", "stack_trace",
	"swagger_exposure", "api_doc_exposure",
	// #11 用户名枚举的类名变体（username_enumeration 走关键词）
	"user_enumeration",
}

// srcBlacklistKeywords 是对声明字段（vulnclass/name/summary）做连写子串匹配的
// 普通黑名单关键词（带升级条件，写明「升级证据」可放行）。保守起见只收录 SRC
// 明确不收、几乎不可能作为合法漏洞名出现的词形——裸「劫持」会误杀会话劫持/
// DNS 劫持等合法高危，只收全词「JSONP 劫持」；「指纹」同理收窄。
var srcBlacklistKeywords = []string{
	// #3 JSONP 劫持 / CRLF 无利用面
	"jsonp劫持", "jsonp", "crlf",
	// #5 弱口令/默认口令
	"弱口令", "默认口令",
	// #1 Self-XSS / 无敏感操作的反射 XSS（反射 XSS 默认在黑名单内，敏感页面
	// 上下文属升级条件——误伤存储型 XSS 对比反射型的提法可由升级证据放行）
	"selfxss", "反射xss", "反射型xss", "reflectedxss", "reflectxss",
	// #2 低危 CSRF（类名 csrf 走精确匹配；中文类型名走这里。不收裸「csrf」
	// 关键词——「CSRF token/防护」在合法漏洞的摘要里太常见，会误杀）
	"跨站请求伪造",
	// #4 信息泄露（报错/目录列表/.git/备份）无进一步利用
	"目录列表", "目录浏览", "git泄露", "git目录", "备份文件泄露", "备份泄露",
	"phpinfo", "源码泄露", "源代码泄露", "堆栈泄露", "调试信息泄露",
	"swagger泄露", "接口文档泄露",
	// #11 用户名枚举/账号存在性
	"用户名枚举", "账号枚举", "账号存在性", "usernameenumeration",
	// #6/#7/#10 显式自称理论/无回显的形态。已证实的越权、未授权敏感数据、
	// 回显 SSRF 是核心可收类型，不按类型拦——由 §三 证据线、§五 复测与
	// 人工隔离区审查把关；这里只拦自己声明「理论/疑似/无回显」的上报。
	"理论idor", "理论越权", "可能存在越权", "疑似越权", "推测越权",
	"可能存在未授权", "疑似未授权",
	"无回显ssrf", "ssrf无回显", "仅dnslog", "dnslog出网", "ssrf仅出网",
}

// srcUpgradeEscape 判定全文是否声明了升级证据。先剔除否定形（「无升级证据」
// 「未提供升级证据」等）再查剩余文本——防止「无升级证据」这类否定句因包含
// 字面标记而误放行。
func srcUpgradeEscape(fullFlat string) bool {
	for _, neg := range []string{
		"无升级证据", "没有升级证据", "未提供升级证据", "未取得升级证据", "未拿到升级证据",
		"缺少升级证据", "缺升级证据", "不含升级证据", "非升级证据", "升级证据不足", "升级证据缺失",
	} {
		fullFlat = strings.ReplaceAll(fullFlat, neg, "")
	}
	return strings.Contains(fullFlat, "升级证据")
}

// SrcFindingTexts 收拢 report_finding 的五个自由文本字段，作为黑名单硬闸的输入。
type SrcFindingTexts struct {
	VulnClass   string
	Name        string
	Summary     string
	Evidence    string
	Description string
}

// SrcFindingBlocked reports whether a report_finding call is blacklisted.
// 匹配范围分级（防止误杀合法漏洞）：
//   - 类型判定只看声明字段（vulnclass/name/summary）——evidence/description
//     里的上下文性提及（如「已排除点击劫持」「不同于反射XSS」）不参与拦截；
//   - 一票否决类（#8/#9：指纹/端口/版本披露、点击劫持）→ 无条件拦截，不看升级证据；
//   - 其余黑名单类 → 声明字段命中且全文无「升级证据」声明则拦截（升级证据
//     写在任一字段都算）；
//   - #6/#7/#10 的「理论/无回显」形态只拦显式标记词，已证实的不拦（见
//     srcBlacklistKeywords 注释）。
func SrcFindingBlocked(t SrcFindingTexts) (bool, string) {
	flat := srcFlat(t.VulnClass) + "\x00" + srcFlat(t.Name) + "\x00" + srcFlat(t.Summary)
	fullFlat := flat + "\x00" + srcFlat(t.Evidence) + "\x00" + srcFlat(t.Description)
	// 一票否决类永远拦截，不看升级证据。
	vc := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(t.VulnClass), " ", "_"))
	for _, c := range srcHardVetoVulnClasses {
		if vc == c {
			return true, c
		}
	}
	for _, kw := range srcHardVetoKeywords {
		if strings.Contains(flat, kw) {
			return true, kw
		}
	}
	if srcUpgradeEscape(fullFlat) {
		return false, ""
	}
	for _, kw := range srcBlacklistKeywords {
		if strings.Contains(flat, kw) {
			return true, kw
		}
	}
	for _, c := range srcBlacklistVulnClasses {
		if vc == c {
			return true, c
		}
	}
	return false, ""
}
