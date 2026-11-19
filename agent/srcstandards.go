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
//  - 黑名单在 addFinding() 做入库硬闸：vulnclass/summary 命中且无升级证据的
//    照常入库但 status='quarantined'（隔离区，可在页面人工检查/放行），不进
//    交付报告（报告只取 confirmed）。
//  - 标准正文可被仓库外文件覆盖：SrcAcceptancePath 指向的文件存在则优先读它，
//    方便按不同 SRC 平台换口径而无需重新编译。

// srcAcceptanceDefault 内嵌默认标准（与 standards/src-acceptance.md 同步维护）。
// 保留在代码里的原因：go run / 单测 / 未随包分发 standards 目录的场景下仍然生效。
const srcAcceptanceDefault = `**SRC 漏洞收取标准（宁缺毋滥——最高优先级纪律）**：
只报告有真实危害、SRC 平台可直接收取的漏洞。无把握一律 record_fact 记 inferred 事实，不报 finding。每条 finding 必须有「完整利用步骤 + 实际响应证据」；理论可利用、前置条件无法满足的一律不报。

**黑名单（默认禁止挖掘/上报；命中且无升级证据的，系统会拒绝入库）**：
1. Self-XSS、无敏感操作的反射 XSS——升级条件：反射点位于鉴权/支付/个人资料等敏感页面上下文
2. 低危 CSRF（改资料类）——升级条件：可触达改绑手机/邮箱、资金、管理等敏感操作
3. JSONP 劫持、CRLF 无利用面——升级条件：能实际带出敏感数据/完成可演示危害
4. 信息泄露（报错/目录列表/.git/备份）无进一步利用——升级条件：从泄露内容实际还原出可利用物（源码→注入点/凭据）
5. 弱口令/默认口令——升级条件：高权账户或可横向影响
6. 理论 IDOR 无数据证明——升级条件：展示了他人真实数据记录
7. 未授权接口但返回无敏感数据——升级条件：返回字段含手机号/订单/身份等业务敏感数据
8. 端口/指纹/版本披露——一票否决，无升级条件
9. 点击劫持、iframe 嵌套——一票否决，无升级条件
10. 无回显/无利用链 SSRF——升级条件：拿到内网实际响应内容并可进一步操作
11. 用户名枚举/账号存在性泄露（响应差异 oracle）——升级条件：从枚举实际走到接管（撞库成功登录他人账号）或批量泄露用户清单本身即敏感数据

**可收取类型的最低证据线（类型命门——命中才算成立，打不出 = 不报）**：
- SQL/NoSQL/SSTI/XXE 注入：有确定输出或副作用证明，**最低共识 = 注出库名 database()**（盲注需时间差+库名内容）；仅报错关键词/报错差异不算。
- 越权/IDOR：**A/B 交叉证明**——A 的资源 B 的 token 能读/改，B 返回内容非空且等于 owner 视图内容；只读到自己、B 返回 []/null ≠ 被拦不算。
- 数据泄露：**他人的数据 + ≥3 个敏感字段 + 非公开/非样例**；自己测试账号的数据 ≠ 漏洞。
- SSRF：服务端发出（回调 UA 证明）+ **必须回显内网数据**（云元数据/内网服务 banner/内网页面）；仅 DNSlog 出网 = 半成品不收。
- 认证绕过/接管：**任意**用户可绕过，不只证明自己能登自己号；OAuth/JWT/密码重置要 A/B 双账号证明。
- RCE/命令执行：真实命令执行实证——能执行命令本身就是危害。
- 业务逻辑/资金：操作**真实生效**且影响**他人**业务状态（金额/订单/状态机），自己测试数据不算。
- 文件上传：webshell 可执行或存储型 XSS 真实触发；只传上去纯存储不解析 = 不成立。
- **不成报清单**：用户名枚举/账号存在性泄露（属中间信号，需结合爆破才转化为危害）、CORS、安全头缺失、Cookie 标志位、单纯密钥/token 泄露（只作高危链证据不单独成报）。

**硬门（所有漏洞必过，缺一不报）**：
1. **先证伪**：假设"这是正常功能"，主动跑否定实验（不存在的值跑同协议排除 catch-all、合法 body 重测排除假阳性）；证伪掉了 = 作废不报。
2. **PoC 可复现**：原始请求块直接粘贴可重放，不需额外上下文。
3. **危害是链路终局**：数据泄露/账户接管/资金损失/RCE/内网横向的**终局结果**，不是中间信号（枚举出用户名、拿到 token、摸清拓扑都不是终点）。
4. **服务端/权限边界确认**：不是浏览器 JS 假象/调试功能/页面渲染。

**定级纪律**：critical=RCE/拖库/直接获取大量真实用户数据/核心账户接管；high=存储 XSS/越权批量数据访问/支付逻辑漏洞；medium=单用户越权/反射 XSS（升级后）/多条件串联泄露；low=前三类都不适用但确有真实危害。拿不准降级不升级，实在拿不准记 fact 交人工判断。`

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
const srcQuarantineNote = "\n\n黑名单命中且无升级证据的上报会被系统拒绝入库；想报黑名单类型，必须先拿到并写明对应的升级证据，否则改记 inferred 事实。"

// srcHighRiskHunting 是中高危漏洞挖掘导向（常驻注入，与收取标准同文件——同为
// 「产出什么漏洞」的纪律，单一事实源）。设计要点：
//   - 覆盖 SRC 中高危的【全部主要类别】，不限于用户举例的 5 类；
//   - 只放「优先级 + 触发启发式」这一层（每轮都在上下文，控制篇幅）；
//   - 深度方法论（载荷递进/绕过清单/gadget 链）不在这里——那是模型自身的能力，
//     写出来是 no-op，只占上下文。
const srcHighRiskHunting = `

**中高危挖掘导向（优先级高于广度铺面）**：SRC 收取的主要是中高危，以下类别按「可收性×危害」优先投入，发现候选点时优先深挖到实际危害再转其他方向：
- **注入类**：SQL 注入（union/报错/布尔/时间盲，注意 JSON 参数、排序字段、in 子句、二次注入）、NoSQL/ORM 注入、模板注入（SSTI，{{7*7}}/${7*7} 类探测，注意 Velocity/Freemarker/Thymeleaf/Jinja2/Twig 特征）、表达式注入（SpEL/OGNL/EL）、XPath 注入。
- **执行类**：命令执行/代码执行（RCE，注意系统命令拼接、eval 类、定时任务/工作流节点）、反序列化（Java：Fastjson/Jackson/Shiro/ Commons-Collections gadget；Python：pickle；PHP：phar/serialize；.NET：ViewState/ObjectStateFormatter——发现序列化数据特征即优先验证）、文件上传绕过（解析漏洞/双后缀/竞态/.htaccess）。
- **SSRF**：所有接受 URL/域名/IP 的参数（webhook、图片/文件抓取、导入、代理、预览、回调地址），探测内网 + 协议（file/gopher/dict），拿到内网响应或链式利用才算。
- **认证与越权**：水平/垂直越权（改 id/遍历，展示他人真实数据）、JWT/session 伪造、密码重置/验证码逻辑缺陷（可接管任意账户）、未授权访问敏感数据接口。
- **业务逻辑**：支付金额/数量篡改、负数/并发竞态（余额/积分/优惠券）、短信轰炸、批量注册、越权操作他人资源。
- **文件包含/读取**：LFI→RCE 链（日志注入/协议封装）、任意文件读取（配置/源码→凭据→二次利用）。
**触发启发式**：参数值出现回显/报错差异、响应时间可操控、返回内容随输入结构变化、看到序列化/模板/表达式语法被解析、URL 参数触发服务端外连——任一命中即把该方向升级为深挖路线，穷尽该类手段再收手。`

// findingGuidanceWithStandards wraps the workflow guidance with the SRC
// acceptance standard. Only agents that can actually produce findings
// (report_finding) get the full discipline; read-only roles are untouched.
func findingGuidanceWithStandards(guidance string) string {
	return guidance + "\n\n" + srcAcceptance() + srcQuarantineNote + srcHighRiskHunting
}

// --- 黑名单匹配（addFinding 硬闸用） ---

// srcBlacklistVulnClasses 是按 vulnclass 精确匹配（不区分大小写/分隔符）的
// 一票否决类。SRC 平台不收的指纹/端口/版本披露、点击劫持等。
var srcBlacklistVulnClasses = []string{
	"version_disclosure", "fingerprint", "port_scan", "port_disclosure",
	"clickjacking", "iframe_clickjacking", "jsonp_hijacking", "jsonp",
	"weak_password", "default_credential", "default_password", "weak_credential",
	"crlf", "crlf_injection", "header_injection", "self_xss",
}

// srcHardVetoVulnClasses 是无升级条件的一票否决类（标准 #8/#9：端口/指纹/
// 版本披露、点击劫持）——写再多「升级证据」也不放行。
var srcHardVetoVulnClasses = []string{
	"version_disclosure", "fingerprint", "port_scan", "port_disclosure",
	"clickjacking", "iframe_clickjacking",
}

// srcHardVetoKeywords 与上表对应的子串关键词（只收不会误伤合法漏洞的词形：
// 「会话劫持」是合法高危，裸「劫持」会误杀，故只收「点击劫持」全词）。
var srcHardVetoKeywords = []string{"点击劫持", "端口扫描", "版本披露", "指纹识别", "指纹泄露"}

// srcBlacklistKeywords 是对 vulnclass + name + summary 做子串匹配的普通黑名单
// 关键词（带升级条件，写明「升级证据：」可放行）。保守起见只收录 SRC 明确
// 不收、几乎不可能作为合法漏洞名出现的词形——裸「劫持」会误杀会话劫持/
// DNS 劫持等合法高危，只收全词「JSONP 劫持」；「指纹」同理收窄。
var srcBlacklistKeywords = []string{
	"点击劫持", "jsonp 劫持", "jsonp", "crlf", "指纹识别", "指纹泄露", "端口扫描", "版本披露",
	"弱口令", "默认口令", "self-xss", "self_xss", "selfxss",
	"用户名枚举", "账号枚举", "账号存在性", "username enumeration",
}

// SrcFindingBlocked reports whether a report_finding call is blacklisted.
// name/summary/evidence/description 参与匹配（vulnclass 是自由文本，模型可能
// 把黑名单信号或升级证据写进任一字段）。分级处理：
//   - 一票否决类（#8/#9：指纹/端口/版本披露、点击劫持）→ 无条件拦截，不看升级证据；
//   - 其余黑名单类 → 文本中出现「升级证据」标记即放行（对应标准表的升级条件列）。
func SrcFindingBlocked(vulnclass, name, summary, evidence, description string) (bool, string) {
	text := strings.ToLower(vulnclass + "\n" + name + "\n" + summary)
	fullText := text + "\n" + strings.ToLower(evidence+"\n"+description)
	// 一票否决类永远拦截，不看升级证据。
	vc := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(vulnclass), " ", "_"))
	for _, c := range srcHardVetoVulnClasses {
		if vc == c {
			return true, c
		}
	}
	for _, kw := range srcHardVetoKeywords {
		if strings.Contains(fullText, strings.ToLower(kw)) {
			return true, kw
		}
	}
	if strings.Contains(fullText, "升级证据") {
		return false, ""
	}
	for _, kw := range srcBlacklistKeywords {
		if strings.Contains(fullText, strings.ToLower(kw)) {
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

// SrcAcceptancePath sets the on-disk override for the SRC acceptance standard
// (server.New wires it to <BaseDir>/standards/src-acceptance.md).
