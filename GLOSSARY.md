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
按固定十节骨架渲染的 Markdown，只收已确认漏洞，不含任务元信息与过程说明；每个漏洞块自足、可单独交给复现方。
_Avoid_: 汇总报告、工作记录、任务报告（指代正文时）

**报告分节（report sections）**:
`finding_report_sections` 中的描述、危害、修复建议、会话四段正文，与一条发现一一对应；与工作摘要 `summary` 分开书写。
_Avoid_: 摘要、详细报告、report 字段
