# ARTEX

ARTEX 是一个 LLM 多智能体自主渗透测试系统：规划者分发意图、worker 执行并把结论写入图，报告模块把确认的发现渲染成交付物。

## Language

**raw 请求（raw request）**:
可直接粘贴进 Burp Repeater 或 Yakit 并发送的 HTTP/1.1 文本报文，包含请求行、头、空行与 body。
_Avoid_: 原始包、HTTP 报文、请求快照、payload

**流量证据快照（traffic evidence snapshot）**:
发现所绑定的一次请求/响应的不可变副本，保存头部、正文哈希与长度；独立于可被删除或归档的抓包记录。
_Avoid_: 抓包记录、流量副本、证据包

**绑定（binding）**:
发现与一条流量证据快照之间的关联，带角色、说明与复现顺序。
_Avoid_: 关联、引用、挂载

**绑定角色（binding role）**:
绑定在复现链路中的用途，分四种：对照、证明、复验、支撑；报告正文只用中文名。
_Avoid_: baseline、proof、verification、supporting（正文中）

**交付报告（deliverable report）**:
按报告骨架渲染的 Markdown，只收已确认漏洞，不含任务元信息与过程说明；每个漏洞块自足、可单独交给复现方。
_Avoid_: 汇总报告、工作记录、任务报告（指代正文时）

**报告分节（report sections）**:
`finding_report_sections` 中的描述、危害、修复建议、会话四段正文，与一条发现一一对应；与工作摘要 `summary` 分开书写。
_Avoid_: 摘要、详细报告、report 字段

**提交稿（submission draft）**:
reporter 在漏洞登记后撰写的单漏洞交付全文，按报告骨架组织并通过骨架校验；与渲染层组装的交付报告、worker 上报的报告分节相区分。
_Avoid_: 详细报告、report 字段、报告全文

**报告骨架（report skeleton）**:
提交稿与交付报告共用的固定十节章节顺序：漏洞名称、漏洞等级、漏洞类型、漏洞影响资产、漏洞URL、漏洞描述、〔测试账号与会话上下文〕、漏洞复现步骤（POC）、漏洞危害、修复建议；提交稿缺必需节会被拒绝入库。
_Avoid_: 模板、章节模板、五节结构

**挖掘方向（hunting focus）**:
规划者在本轮目标集里声明的漏洞类型偏向，决定探索力气往哪些类型投；与只管「报不报、怎么报」的收取纪律相对。
_Avoid_: 漏洞偏好、类型偏好、挖掘偏好

**类型分布（type distribution）**:
本任务已产出 finding 按 vulnclass 归类的计数快照，注入规划者上下文供其自纠偏；是运行时观测数据，不是标准。
_Avoid_: 类型统计、类型清单、产出统计

**同类上限（same-type cap）**:
对单一漏洞类型在单任务内有效产出（pending + confirmed，排除隔离/误报/重复/忽略）的数量上限（默认 3）；触顶即停止该方向继续投入，转向其他类型。镜像 SRC 平台「厂商保护机制」。
_Avoid_: 类型配额、类型限额、去重上限

**规范类型名（canonical type name）**:
挖掘方向节为每类漏洞给定的标准中文名；vulnclass 按它填写，类型分布与同类上限都按折叠到它的桶计算；词表存于 standards 热载文件，不进代码常量。
_Avoid_: 类型标签、规范名、canonical name（正文中）
