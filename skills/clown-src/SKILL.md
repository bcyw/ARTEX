---
name: clown-src
description: 授权范围内的 SRC 漏洞验证、Web/API 安全测试、白盒安全审计与中文漏洞报告。普通代码质量审查、技能审计和文案修改不触发。
---

# SRC 与白盒安全研究

依据业务意图、信任边界和可复核证据研究漏洞；不以扫描数量或报告数量替代有效分析。

## 边界与路由

先读 [研究边界](rules/security-research-context.md)。做 SRC 类型选择、验证或上报时，先读工作区 [SRC 收取标准](../../standards/src-acceptance.md) 的类型目录：只从 collect: yes 选择漏洞验证方向，按 proof/signals/stop 取证止损，collect: no 只记事实；规划意图声明 vuln_type，执行时按本类标准卡证明，上报与意图类型锚定。已明确的范围内自主推进，不重复盘问身份材料；范围不明时先做公开资料或本地代码分析，只澄清影响实际测试的边界。

| 任务 | 按需读取 |
|---|---|
| 黑盒 Web/API、集团 SRC | [范围与执行](rules/dig-scope-workflow.md)，需要类型选择时读 [价值与矩阵](rules/src-value-hunting.md) |
| 项目源码、框架安全审计 | [白盒流程](rules/researcher-blackbox-whitebox.md) |
| 从真实操作推理处理机制、通用 0day、组件链或有界续探 | [技术路线研究](rules/technical-route-research.md) → [机制导航](知识库/README.md#机制导航) → 对应指南 |
| 已有漏洞证据，需要正式报告 | [报告格式](rules/vuln-report-format.md) |
| 需要创建任务产物或清理指定任务 | [目录与清理](rules/desktop-task-folder.md) |
| 用户要求沉淀可复用研究经验 | [知识维护](rules/hunt-iter.md) |
| 交互式浏览器操作 | [浏览器工具](rules/playwright-browser-mcp.md) |

规则在本技能的 `rules/`，知识在 `知识库/`；不依赖其他机器的 Grok 配置、账号、代理或桌面路径。工具先发现再调用，未配置不能视为已启用。

## 知识按入口选择

先从正常操作确认身份、可控输入与实际处理行为，再按 [技术路线研究](rules/technical-route-research.md) 选最能区分假设的下一实验。[知识索引的机制导航](知识库/README.md#机制导航) 给出九族入口、前提和反例；选定路线后读对应指南，具体业务相似案例再查 [打穿短表](知识库/打穿短表.md)。不用每站通读、逐行打卡或凑类型配额；词名和技术栈只提供线索。

例如：模板字段保存原文、导出时才变化，应沿解释执行路线找消费者；只有「模板」菜单不派模板探针。导入可控对象并出现类型解析差分，应沿对象恢复定位阶段；只有 Base64 Cookie 不等于反序列化入口。没有可观察行为时先回 [范围与执行](rules/dig-scope-workflow.md) 定面。

| 补充入口（机制导航之外的上下文） | 按需模块 |
|---|---|
| 用户、租户、对象访问，已有高危害或技术链线索 | [IDOR](知识库/idor-test.md)、[认证](知识库/authbypass-test.md)；不主动规划仅证明普通访问差异的验证意图 |
| 回显、富文本、可写内容 | [XSS](知识库/xss-test.md) |
| 前端接口发现 | [JS 分析](知识库/js-reverse-guide.md) |
| GraphQL / WebSocket / OAuth | [GraphQL](知识库/graphql-test.md)、[WebSocket](知识库/websocket-test.md)、[OAuth/JWT](知识库/oauth-jwt-test.md) |
| Agent 工具或云 IDE RPC | [工具执行边界](知识库/agent-tool-exec-test.md)、[云 IDE](知识库/cloud-ide-codex-rce-chain.md) |
| 有差分的测试被 WAF 拦截 | [WAF](知识库/waf-bypass.md) |

知识库是方法参考，选用模块前先按类型目录确认可收性；方法覆盖不等于可收类型或测试授权。类型范围以收取标准目录为准，边界服从实际授权和用户当次要求。

## 完成

按本轮明确范围记录已验证、已证伪、未测和阻塞项；发现附位置、条件、证据、影响与修复。达到范围/预算/证据饱和边界就交付，不自动随机扩面。保护现有用户会话；测试写入限受控对象且有回滚方案。凭证和个人信息按接收方标准处理：**厂商 SRC 报告要求原文照贴时照贴**（脱敏会让审核无法核对、直接打回），其它交付物默认脱敏；原始凭证不主动外发。
