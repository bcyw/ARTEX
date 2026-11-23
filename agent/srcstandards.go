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
//  - 标准正文可被仓库外文件覆盖：SrcAcceptancePath 指向的文件存在则优先读它，
//    方便按不同 SRC 平台换口径而无需重新编译。
//  - 类型归属、同类上限与折叠映射的唯一机器来源是正文末尾的「机器可查目录」
//    （~~~types 围栏块），由 agent/srchunting.go 现读现解析；正文其余章节是
//    人类可读说明，不改机器语义。

// srcAcceptanceDefault 内嵌默认标准（与 standards/src-acceptance.md 同步维护）。
// 保留在代码里的原因：go run / 单测 / 未随包分发 standards 目录的场景下仍然生效。
const srcAcceptanceDefault = `**SRC 漏洞收取标准（宁缺毋滥——最高优先级纪律）**：
只报告有真实危害、SRC 平台可直接收取的漏洞。无把握一律 record_fact 记 inferred 事实，不报 finding。每条 finding 必须有「完整利用步骤 + 实际响应证据」；理论可利用（仅 dnslog 回连/仅可爆破/仅报错）、前置条件无法满足的一律不报。
规划者从文末类型目录选择 collect: yes 的类型建意图；执行者按本类标准卡取证止损，拿不到证明物记 fact；上报类型与意图锚定，省略 vulnclass 时沿用意图类型，不得改报其他类型。名称/摘要中的词语不参与类型判定。

**公开性检查（每条 finding 上报前必过——回答：这是不是"符合业务预期的产品设计"？）**：
以未登录/无凭据会话判定，任一命中即设计如此，作废记 fact：
1. 内容公开性：数据本来就无鉴权公开可达且无叠加攻击面（用户名/邮箱/公开 UUID/robots.txt/版本 banner/报错串 = 公开信息，不构成漏洞）。
2. 意图公开性：行为见于官方文档/正常业务流程，或入口本就面向公众（公开主页/分享页/排行榜/公开 API）。判定看危害是否为 0，不是"看起来奇怪"。
密钥例外：真实密钥/凭据泄露不受公开性豁免（公开性只豁免无危害信息，不豁免可利用凭据）。
完成判据：找到未登录可见的正常前端入口拿到同样数据 → 作废；找不到入口且同域基线接口确实拒绝匿名 → 通过。

**明确不收类型（默认禁止挖掘/上报；机器侧只读文末类型目录，collect: no 规划拒建、上报拒收并引导 record_fact；升级后由规划者按实际危害另选可收类型建意图，worker 不临时改报类型）**：
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
11. 用户名/账号/手机号枚举、存在性与注册状态泄露（响应差异 oracle）——升级条件：从枚举实际走到接管（撞库成功登录他人账号）或批量泄露的用户清单本身即敏感数据
12. 短信轰炸/无频控发码（骚扰类）——升级条件：从发码链实际走到任意账户接管或真实资损；仅无频控、匿名可发、可跨号下发均不收
13. 仅凭状态码/报错/响应差异判定的"漏洞"（403→200、500 报错、响应不同）——升级条件：从差异实际还原出数据或完成操作（盲注需时间差+数据内容）；差异本身永远不是危害

**危害最小证明物（按类型——拿不出证明物 = 不成立，报了也会被平台驳回）**：
- SQL/NoSQL/SSTI/XXE 注入：**注出一条真实数据**（最低共识 = 注出库名 database()；盲注需时间差+库名内容）；仅报错关键词/报错差异不算。
- 越权/IDOR：**A/B 交叉证明**（A 的资源 B 的 token 能读/改，B 返回非空且等于 owner 视图内容）**+ 公开性检查通过**（该数据在正常前端无未登录可见路径）；只读到自己、B 返回 []/null ≠ 被拦不算。
- 数据泄露：**他人的数据 + ≥3 个敏感字段 + 非公开/非样例 + 公开性检查通过**；自己测试账号的数据 ≠ 漏洞。
- SSRF：服务端发出（回调 UA 证明）+ **必须回显内网数据**（云元数据/内网 banner/内网页面）；仅 DNSlog 出网 = 理论可行不收。
- 认证绕过/接管：**任意**用户可绕过，不只证明自己能登自己号；OAuth/JWT/密码重置要 A/B 双账号证明。
- RCE/命令执行：真实命令执行实证——能执行命令本身就是危害。
- 业务逻辑/资金：操作**真实生效**且影响**他人**业务状态（金额/订单/状态机），自己测试数据不算。
- 文件上传：webshell 可执行或存储型 XSS 真实触发；只传上去纯存储不解析 = 不成立。
- **不成报清单**：用户名/账号/手机号枚举、短信轰炸、仅状态码/报错差异、CORS、安全头缺失、Cookie 标志位、单纯密钥/token 泄露（只作高危链证据不单独成报）。

**硬门（所有漏洞必过，缺一不报）**：
1. **先证伪**：假设"这是正常功能"，主动跑否定实验，三类：不存在的值跑同协议排除 catch-all、合法 body 重测排除假阳性、**公开性检查**排除设计如此；任何一类证伪掉 = 作废不报。
2. **PoC 可复现**：原始请求块直接粘贴可重放，不需额外上下文。
3. **危害是链路终局**：数据泄露/账户接管/资金损失/RCE/内网横向的**终局结果**，不是中间信号（枚举出用户名、拿到 token、摸清拓扑、状态码/报错差异都不是终点）。
4. **服务端/权限边界确认**：不是浏览器 JS 假象/调试功能/页面渲染。

**查重（上报前必查）**：同一资产 + 同一根因 + 同一接口 + 同一影响面 = 同一漏洞，补强已有 finding，不新写；先查探索图与已有 findings 再上报。

**不挖清单（挖掘阶段直接跳过，不是报不报的问题）**：
以下方向一开始就不要投入探索——要么不在 SRC 收取范围，要么中间信号成报率极低。发现候选点只允许花 1-2 次请求确认能否升级到链路终局，不能升级立刻放弃并记 fact 转向，不许深挖（这些方向同步登记为文末目录的 collect: no 条目，规划期拒建、上报期拒收）：
1. 用户名/账号/手机号枚举、注册状态/存在性 oracle：响应差异本身不收；只有能继续走到撞库接管、任意密码重置、或枚举产物本身即敏感数据清单时才投入，且投入点在「下一步利用」，不是「再验证几遍差异」。
2. 短信轰炸/无频控发码：骚扰类危害基本不收；发码接口只在验证码可预测/可绕过（→认证接管链）或发码进入其他高危链（如配合越权改绑）时继续，纯「无频控、可跨号、无图形码」到此为止。
3. 仅凭状态码/报错/响应差异判定的"漏洞"：403 变 200、500 报错、响应长度/结构不同——都不是漏洞，只是信号；基于差异的候选必须先回答「差异背后的危害是什么」，用数据或操作证明，不能只拿差异本身当结论。
4. 纯扫描器/指纹/端口/版本类产出：记 fact 供后续利用，永不成报。
5. 批量注册/垃圾提交/留言污染类：匿名表单可无限提交是设计如此（公开业务流程），不构成危害。

**挖掘方向**：
探索力气按「**可收性 × 危害 × 证据**」分配：真实入口上的具体中间证据、可控危险输入或明确组件利用链优先，只有技术栈猜测的路线低优先。类型目录限定可收类型与证明物，type_coverage 检查触顶，不是必测配额，也不按目录顺序覆盖。声明 vuln_type 与 proof（缺省取目录证明物）；纯侦察可省略类型。执行者按本类标准卡 proof/signals/stop 取证止损，拿不到证明物记 fact；上报与意图类型锚定，按证据如实定级。
1. **注入类**：SQL/NoSQL/ORM 注入、模板注入（SSTI）、表达式注入（SpEL/OGNL/EL）、XPath/XXE。触发启发式：参数值回显或报错差异、响应时间可操控、返回内容随输入结构变化、模板/表达式/序列化语法被解析。
2. **命令执行与反序列化**：RCE/命令执行/代码执行、反序列化利用链（Fastjson/Jackson/pickle/phar/ViewState）、定时任务与工作流节点。触发启发式：系统命令拼接、eval 类入口、出现序列化数据特征即优先验证。
3. **SSRF**：所有接受 URL/域名/IP 的参数（webhook、图片/文件抓取、导入、代理、回调地址），探测内网 + 协议（file/gopher/dict）。触发启发式：URL 参数触发服务端外连，拿到内网实际响应才算。
4. **认证绕过与账户接管**：JWT/session 伪造、密码重置/验证码逻辑缺陷、OAuth 回调缺陷。触发启发式：任意用户可绕过才算（OAuth/JWT/密码重置要 A/B 双账号证明）。
5. **存储型 XSS**：内容持久化后在他人生效上下文触发（个人资料/评论/工单），能打到他人 cookie 或管理员；反射型按明确不收类型 #1 处理（敏感页面上下文可升级）。触发启发式：输入入库后出现在他人可见页面且未编码。
6. **文件上传 getshell**：解析漏洞、双后缀、竞态、.htaccess。触发启发式：webshell 可执行才算，纯存储不解析不成立。
7. **业务逻辑**：支付金额/数量篡改、负数与并发竞态（余额/积分/优惠券）、订单与状态机篡改、越权操作他人资源。触发启发式：操作真实生效且影响他人业务状态，自己测试数据不算。

**访问差异与真实危害**：不主动规划仅证明普通访问差异的验证意图；普通越权/未授权线索主要作为技术链入口。批量敏感数据、核心账户接管等真实高危害仍可验证上报，保留 A/B 交叉证明、公开性检查与既有证据/定级标准，同类触顶后停止新增投入。

**同类上限（默认 3，文末机器可查目录维护）**：单任务内同一规范类型的有效产出（pending + confirmed）达到上限即触顶——继续上报会被拒收并引导补强已有 finding 或改记 fact；已隔离/误报/重复的产出不占名额。触顶是引导信号不是质量否决，规划者应把意图分散到未触顶方向。

**别名折叠（vulnclass 写法归一）**：任意写法先做机械归一（大小写/空白/连字符），再查文末目录折叠到规范名；规划期仅接受目录中 collect: yes 的类型，目录外类型先补目录再建漏洞验证意图。上报期没有类型化意图锚定时，目录外新写法仍自成一桶、照常计数并允许上报；有锚定时须与意图类型一致。

**定级纪律**：定级锚 SRC 平台体系（严重/高/中/低），不写 CVSS 分数；无 exploit 评分封顶【中】。critical=RCE/拖库/直接获取大量真实用户数据/核心账户接管；high=存储 XSS/越权批量数据访问/支付逻辑漏洞；medium=单用户越权/反射 XSS（升级后）/多条件串联泄露；low=前三类都不适用但确有真实危害。拿不准降级不升级，实在拿不准记 fact 交人工判断。

**复测纪律**：复测结论 reproduced 才算有效佐证；连续 2 次复测无法复现 → 标记 false_positive。已绑定的流量证据快照含完整利用响应（证明角色）时，可作为已有利用证据；历史证据不替代独立复测中的本次实际验证。AI 生成的报告必须依据实际验证证据（请求/响应原文、命令输出或日志），不能用推测补齐危害。流量绑定可选，未采集和非 HTTP 场景保留已有可核验证据；不为补包重复探测，不在交付报告中写缺失流量等过程说明。

**技术利用路线的续探与止损**：
- 路线身份：按任务 + 入口 + 机制族 + 相关组件/参数确定。改变摘要、payload、机制拼写或意图 ID 不重置去重与预算；同一入口下应填入有区分度的组件/参数。
- 状态完整：路线应保留入口、机制族、组件/参数、假设、前置条件、已测变体、结果与剩余假设，并可从既有意图和事实恢复。
- 有界续探：同入口同机制族默认最多创建 6 次执行意图（续跑也计数），运行配置可调整；上限不是目标。危害已证实（impact）、路线级有效阴性（negative）、前置条件可靠证伪（prerequisite_disproved）或关键变体耗尽（variants_exhausted）时立即停止。
- 信息增量：同路线后续意图必须带来此前未用于该路线的新 fact/finding，或新的 tested 变体。仅更换 summary、next_step、payload、outcome 措辞不算增量；自由文本不能绕过计数。
- 无信息换向：连续 3 个规划轮次同路线没有新增机制、入口、组件/版本、交互、关键响应或 tested 变体时换方向；出现新信息则重置计数。
- 优先级：全局任务预算、worker 超时、任务取消、人工停止与既有类型上限优先于路线续探。触顶、有效阴性或预算耗尽时，不得以“类型尚未覆盖”等理由提权重派；调整优先级须记录理由。
- 状态区分：progress（路线进展）、negative（有效阴性）、blocked（技术受阻）、no_interaction（健康窗口暂无交互）、service_unavailable（OOB 服务不可用）、observation_incomplete（观察窗口未完成）、insufficient_impact（有交互但危害不足）与 impact/prerequisite_disproved/variants_exhausted 必须保持不同状态，不得统一折叠为失败。
- OOB 解释：暂无交互或 OOB 服务故障不证明目标无漏洞，不计作路线新信息，也不自动触发整个 worker 重试；回调只是中间证据，仍需继续取证到实际危害。

**机器可查目录（类型归属与上限的唯一机器来源）**：
本块是 Go 侧（规划选型、标准卡、上报类型归属、同类上限、类型覆盖态势与别名折叠）读取的唯一机器来源，热改后下一次读取即生效，无需重编译或重启；已存意图的显式 proof 保留。正文的明确不收类型、不挖清单、挖掘方向只做人类可读说明，若与目录冲突以目录为准。行格式：cap: <数字> 全局同类上限（缺省 3）；type: <规范名> 开启一条类型，collect: yes 可收（受同类上限约束）/ collect: no 明确不收（规划拒建、上报拒收）；aliases: <别名…> 空格分隔的单 token 别名（折叠时抹掉空白/大小写/连字符，每个别名内部不要带空格）；proof: 危害最小证明物；signals: 触发启发式；stop: 止损线（collect: no 条目的拒收文案来源）。

~~~types
cap: 3
type: 注入类
collect: yes
aliases: sql注入 sqli sql_injection nosql注入 nosql_injection ssti 模板注入 xxe xpath注入 表达式注入 orm注入
proof: 注出一条真实数据（最低共识 = 注出库名 database()；盲注需时间差 + 库名内容）；仅报错关键词不算
signals: 参数值回显或报错差异、响应时间可操控、返回内容随输入结构变化、模板/表达式/序列化语法被解析
stop: 拿不出真实数据证明物即不成立，改记 fact

type: 命令执行与反序列化
collect: yes
aliases: rce 命令执行 代码执行 命令注入 command_injection deserialization insecure_deserialization 反序列化 fastjson jackson pickle phar viewstate
proof: 真实命令执行实证（能执行命令本身就是危害）
signals: 系统命令拼接、eval 类入口、出现序列化数据特征即优先验证
stop: 只有序列化特征无执行实证不成立，改记 fact

type: SSRF
collect: yes
aliases: ssrf 服务端请求伪造 server_side_request_forgery
proof: 服务端发出 + 回显内网数据（云元数据/内网 banner/内网页面）；仅 DNSlog = 理论可行不收
signals: URL 参数触发服务端外连，拿到内网实际响应才算
stop: 仅 DNSlog 出网无回显不成立，改记 fact

type: 认证绕过与账户接管
collect: yes
aliases: auth_bypass 认证绕过 authentication_bypass 账户接管 account_takeover login_bypass jwt伪造 session伪造 密码重置 验证码绕过
proof: 任意用户可绕过；OAuth/JWT/密码重置要 A/B 双账号证明
signals: 任意用户可绕过才算（OAuth/JWT/密码重置要 A/B 双账号证明）
stop: 只能登自己号不算绕过，改记 fact

type: 存储型 XSS
collect: yes
aliases: stored_xss 存储xss 存储型xss xss_stored
proof: webshell 可执行或存储型 XSS 真实触发；纯存储不解析不成立
signals: 输入入库后出现在他人可见页面且未编码
stop: 仅自触发不危害他人不成立，改记 fact

type: 文件上传 getshell
collect: yes
aliases: file_upload 文件上传 upload_getshell webshell getshell 任意文件上传 解析漏洞
proof: webshell 可执行或存储型 XSS 真实触发；纯存储不解析不成立
signals: webshell 可执行才算，纯存储不解析不成立
stop: 纯存储不解析不成立，改记 fact

type: 业务逻辑
collect: yes
aliases: business_logic 业务逻辑 逻辑漏洞 支付逻辑 竞态 条件竞争 支付绕过 金额篡改 负数下单
proof: 操作真实生效且影响他人业务状态；自己测试数据不算
signals: 操作真实生效且影响他人业务状态，自己测试数据不算
stop: 只影响自己测试数据不成立，改记 fact

type: 越权
collect: yes
aliases: idor 越权 水平越权 垂直越权 unauth 未授权 unauthorized broken_access_control
proof: A/B 交叉证明（A 的资源 B 的 token 能读/改，B 返回非空且等于 owner 视图内容）+ 公开性检查通过
signals: 只读到自己不算；B 返回空且等于 owner 视图内容才算
stop: 只读到自己或过不了公开性检查不成立，改记 fact

type: 反射型 XSS 与 Self-XSS
collect: no
aliases: 反射xss 反射型xss reflected_xss reflect_xss xss_reflected self_xss selfxss self型xss
proof: 反射点位于鉴权/支付/个人资料等敏感页面上下文（升级条件）
signals: 反射点在敏感页面上下文才可升级为存储型 XSS 或敏感反射
stop: 无敏感操作的反射 XSS 与 Self-XSS 不成报，改记 fact；敏感上下文请改报存储型 XSS

type: 低危 CSRF
collect: no
aliases: csrf 跨站请求伪造
proof: CSRF 可触达敏感操作（改绑手机/邮箱、资金操作、管理操作）
signals: 可触达改绑/资金/管理等敏感操作才算
stop: 改资料类低危 CSRF 不成报，改记 fact；触达敏感操作请改报对应越权/账户接管

type: JSONP 劫持与 CRLF 无利用面
collect: no
aliases: jsonp jsonp劫持 crlf header_injection
proof: 能实际带出敏感数据 / 完成可演示的危害
signals: 能带出敏感数据或完成可演示危害才算
stop: 无利用面的 JSONP/CRLF 不成报，改记 fact；能带出数据请改报数据泄露

type: 信息泄露无进一步利用
collect: no
aliases: 目录列表 目录浏览 git泄露 git目录 备份文件泄露 备份泄露 phpinfo 源码泄露 源代码泄露 堆栈泄露 调试信息泄露 swagger泄露 接口文档泄露 directory_listing git_exposure source_leak stack_trace debug_info
proof: 从泄露内容实际还原出可利用物（如源码→拿到注入点/凭据）
signals: 从泄露内容实际还原出可利用物才算
stop: 报错/目录列表/.git/phpinfo 本身不是危害，改记 fact；还原出利用物请改报对应可收类型

type: 弱口令与默认口令
collect: no
aliases: 弱口令 默认口令 weak_password default_credential default_password weak_credential
proof: 登录的是高权账户或可横向影响
signals: 高权账户或可横向影响才算
stop: 弱口令/默认口令不成报，改记 fact；高权登录请改报账户接管

type: 端口指纹版本披露
collect: no
aliases: 端口扫描 版本披露 指纹识别 指纹泄露 port_scan port_disclosure version_disclosure fingerprint
proof: 无（一票否决）
signals: 无
stop: 端口/指纹/版本披露本身不是危害，改记 fact 供后续利用，永不成报

type: 点击劫持与 iframe 嵌套
collect: no
aliases: 点击劫持 iframe嵌套 clickjacking iframe_clickjacking ui_redressing
proof: 无（一票否决）
signals: 无
stop: 点击劫持/iframe 嵌套不成报，改记 fact

type: 用户账号手机号枚举
collect: no
aliases: 用户名枚举 账号枚举 账号存在性 手机号枚举 手机号存在性 username_enumeration user_enumeration phone_enumeration mobile_enumeration
proof: 从枚举实际走到接管（撞库成功登录他人账号）或批量泄露的用户清单本身即敏感数据
signals: 从枚举走到接管或枚举产物本身即敏感清单才算
stop: 响应差异枚举本身不是危害，改记 fact；走到接管请改报账户接管

type: 短信轰炸与无频控发码
collect: no
aliases: 短信轰炸 骚扰短信 短信骚扰 轰炸短信 无限发短信 sms_bombing sms_bomb sms_flood sms_flooding
proof: 从发码链实际走到任意账户接管或真实资损
signals: 发码链走到接管或资损才算
stop: 仅无频控/匿名可发/可跨号下发均不成报，改记 fact；走到接管请改报账户接管

type: 仅凭状态码报错响应差异
collect: no
aliases: 仅凭状态码 仅状态码 仅凭响应差异 仅响应差异 仅凭报错差异 状态码差异即漏洞 报错差异即漏洞
proof: 从差异实际还原出数据或完成操作（盲注需时间差 + 数据内容）
signals: 从差异还原出数据或操作才算
stop: 差异本身永远不是危害，改记 fact；还原出数据/操作请改报对应可收类型

type: 无回显 SSRF
collect: no
aliases: 无回显ssrf ssrf无回显 仅dnslog dnslog出网 ssrf仅出网 blind_ssrf
proof: 拿到内网实际响应内容并可进一步操作
signals: 拿到内网实际响应才算
stop: 仅 DNSlog 出网无回显不成报，改记 fact；拿到回显请改报 SSRF

type: 理论 IDOR 无数据证明
collect: no
aliases: 理论idor 理论越权 可能存在越权 疑似越权 推测越权 theoretical_idor
proof: 展示了他人真实数据记录
signals: 展示他人真实数据记录才算
stop: 仅理论/疑似越权不成报，改记 fact；展示他人数据请改报越权

type: 未授权接口无敏感数据
collect: no
aliases: 可能存在未授权 疑似未授权
proof: 返回字段含手机号/订单/身份等业务敏感数据，且该接口非公开页面数据源（过公开性检查）
signals: 返回敏感数据且过公开性检查才算
stop: 未授权但无敏感数据不成报，改记 fact；返回敏感数据请改报越权

type: 批量注册与垃圾提交
collect: no
aliases: 批量注册 垃圾提交 留言污染 批量提交
proof: 无（公开业务流程，设计如此）
signals: 无
stop: 匿名表单可无限提交是设计如此，不构成危害，改记 fact
~~~`

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

// srcHighRiskHunting 是中高危挖掘的行为纪律（常驻注入，与收取标准同文件——同为
// 「产出什么漏洞」的纪律）。类型优先级清单【不在这里】：它活在上方收取标准的
// 「类型目录」（热载、免重编译可调），本常量只保留类型中性的纪律层——单一事实源，
// 代码零漏洞类型字符串（ADR-0004）。
const srcHighRiskHunting = `

**中高危挖掘导向**：挖掘方向按真实入口与具体中间证据、可控危险输入或明确组件利用链安排优先级，只有技术栈猜测保持低优先。规范类型名、collect: yes 与证明物以类型目录为准；type_coverage 用于触顶检查，不是补齐覆盖的任务。执行者按本类标准卡证明，上报与意图类型锚定。
**证据推进**：把“观察到什么、据此推断什么、还缺什么证明”分开。每次验证只解决一个决定路线去留的关键问题，先给出假设成立与不成立各应出现的可观察结果，再选择能区分二者的最小实验；响应差异需要排除身份、缓存、输入合法性与环境变化等替代解释。下一步应缩小关键不确定性，而不是增加同义请求数量。
**危害边界**：以中危、高危、严重的真实影响为挖掘方向，不预设结果等级或发现数量。有效证明同时说明可控输入、越过的信任边界、已观察影响和必要前置条件；区分最小样本已证实的能力与尚未验证的规模，不靠扩大数据获取或业务变更抬高等级。
**触发启发式**：回显/报错差异、可控时序、结构变化、语法解析或服务端外连可支持技术假设；以可复核证据为依据，在预算内尝试非破坏性变体，不要求穷尽所有手段。
**止损线（与深挖同等重要）**：先过公开性检查。技术利用路线按任务 + 入口 + 机制族 + 相关组件/参数确定稳定身份；同入口同机制族默认最多执行 6 次意图（续跑也计数，运行配置可调），上限不是目标。危害已证实、有效阴性、前置条件可靠证伪、关键变体耗尽、类型触顶或全局控制要求停止时立即结束，不因覆盖缺口重派。连续 3 个规划轮次没有新增证据或 tested 变体时换方向，新信息重置计数。仅换摘要、payload、结果措辞或意图 ID 不算增量。OOB 暂无交互、观察未完成或服务故障不证明目标无漏洞，不计进展，也不自动重跑 worker；只有回调仍需取证到实际危害。
**响应差异不是漏洞**：回显/报错差异、状态码变化、响应结构不同只是**信号**，用来定位值得深挖的参数；任何基于差异的候选必须先回答「差异背后的危害是什么」，拿数据或操作证明，只拿差异本身当结论的一律作废。短信轰炸、用户名/账号枚举按上文「不挖清单」处理：默认不投入，只有能走到认证接管/真实资损/敏感数据终局才跟进。`

// findingGuidanceWithStandards wraps the workflow guidance with the SRC
// acceptance standard. Only agents that can actually produce findings
// (report_finding) get the full discipline; read-only roles are untouched.
func findingGuidanceWithStandards(guidance string) string {
	return guidance + "\n\n" + srcAcceptance() + srcHighRiskHunting
}
