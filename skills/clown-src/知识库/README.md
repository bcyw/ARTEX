# 知识库索引

实战方法论 / 测试清单 / 场景矩阵。与 `SKILL.md` 流程配合使用。

## 使用约定

- 按 [技术路线研究](../rules/technical-route-research.md) 从正常操作定位当前处理阶段，再用下表选指南；需要相似业务案例时查 [打穿短表](打穿短表.md)。无真实入口先定位可证伪假设，不默认派越权/认证/注入兜底。超长篇按需读取，禁止每站通读本目录。
- 磁盘有 `*src经验.md` 才开专篇，没有不算缺。开 `SKILL.md` 不会再带集团日记
- 矩阵是方法索引，不是类型覆盖配额。以具体证据、危险输入或组件链选方向；普通越权/未授权主要作为入口，不主动规划仅证明普通访问差异的验证意图。真实高危害仍按标准证明与上报。
- 方便和能力优先；省 token 是顺带，不挡开模块
- 短表点名的手法用标题搜；历史案例必须核对当前入口、版本、配置与消费者。纠正不成立的结论与重复内容，不把保留旧手法当成强制执行理由。
- 篇内跳转已改成本目录真实文件（`idor-test.md` 一类）；不要再跟 `../xxx/SKILL.md`
- 知识库与 `rules/` 冲突时 **以 rules 为准**（挖什么 `src-value`；CORS 不挖 `cors-vuln-report-priority`；写不写 `vuln-report-format`）
- **`cors-test.md` / `llm-security-test.md`：不挖/禁开越狱。** `401-403-bypass.md` 不磨登录 HTML。
- 正式 SRC 报告：`rules/vuln-report-format.md`

## 机制导航

每行给一个正例及其必要前提、一个不应据此派验证的反例。只选当前证据支持的族；同一个字段可在后续阶段切换路线，机制族不等于报告类型。

| 机制族 | 可进入的实际行为与前提（正例） | 不足以进入或需要改判的反例 | 指南 |
|---|---|---|---|
| 解释执行 | 可控文本被模板、表达式、脚本或命令消费者解释；如保存的邮件模板在发送时求值，且能触发/观察自己的测试对象 | 只有菜单叫「模板」、浏览器自行替换、或产品允许的公式计算；没有额外信任边界证据 | [模板/表达式/延迟解释](el-injection-test.md)；真实工具调用另见 [工具执行](agent-tool-exec-test.md) |
| 对象恢复 | 导入、会话或队列的可控内容进入原生对象流、多态类型绑定或自定义恢复；能关联格式/类型/恢复阶段差分 | 只有 Base64、JSON、类库名称；只解析普通键值或在完整性校验前已拒绝 | [对象恢复与反序列化](deserialization-test.md) |
| 查询 | 正常筛选/排序/字段选择/报表能改变服务端查询，已定位输入位置及结果观察面 | 只有搜索框；正常全文搜索命中 `or`、预期筛选变化或一次慢请求 | [查询机制](injection-test.md) |
| 文件 | 自己的文件被接收、存储、解包、转换或后续消费；可控字节/路径至少影响其中一段 | 仅获上传 URL/下载附件；自有对象可覆盖不等于任意覆盖或执行 | [文件生命周期](file-upload-test.md)、[路径与包含](path-traversal-lfi-test.md) |
| 资源获取 | URL、导入配置、远程图片或回源规则使服务端请求资源；能关联发送方、请求能力及消费者 | URL 只是保存/回显、请求来自本机浏览器、或只有健康检查 DNS；外网回连不等于内网影响 | [资源获取/SSRF](ssrf-test.md) |
| 分层规范化 | 网关与应用、校验器与消费者对同一编码/路径/参数有不同解释；明确两端如何解码、选值和消费，有正常资源与层间差分对照 | 单个 400/404/WAF 拒绝；不知道哪两层解释不同就轮换编码 | [网关](api-gateway-test.md)、[路径](path-traversal-lfi-test.md) |
| 跨请求/缓存 | 前一请求影响后续受控请求；能关联顺序、连接/共享状态、缓存键和响应归属，区分独立与复用条件 | 缓存 HIT 静态壳、同一身份正常缓存、孤立超时，没有跨请求因果关联 | [缓存](cache-poisoning-test.md)、[请求边界](http-smuggling-test.md) |
| 身份信任 | 会话、签名、联合身份或对象归属跨边界被错误承认；明确签发者、消费者、用途和主体绑定，有受控身份与正常拒绝对照 | 票据可解码、签名/身份字段存在、租户管理员本职访问；未确定票据应被谁用于何事 | [认证](authbypass-test.md)、[OAuth/JWT](oauth-jwt-test.md)、[对象权限](idor-test.md) |
| 状态并发 | 审批、余额、库存等不变量在顺序/重放/并发中可能失守；可控制顺序/时序，有可回滚对象、串行对照和最终持久状态 | 重复 200、队列接受两次、UI 未刷新，但最终状态与账目正常 | [业务状态](logic-test.md)、[竞态](race-condition-test.md) |

## 文件清单

| 文件 | 说明 |
|------|------|
| `打穿短表.md` | 挖洞手法索引（一行/指针；正文仍在各模块） |
| `401-403-bypass.md` | **禁开磨登录 HTML**（已收成一行）；业务 API 401 现场自己打 |
| `api-gateway-test.md` | API 网关 |
| `agent-tool-exec-test.md` | 对话口工具真执行（不是越狱、不是云 IDE RPC） |
| `authbypass-test.md` | 认证绕过（未登录改密/IDaaS + 短表指针；英文字典已砍） |
| `cache-poisoning-test.md` | 缓存投毒/欺骗（原有+补充） |
| `clickjacking-test.md` | 缺头不写（已收成一行） |
| `cloud-ide-codex-rce-chain.md` | 云 IDE/Codex 系：弱口令→RPC RCE→集群/API Key 链（短表有指针） |
| `cors-test.md` | **不挖勿开**（已收成一行） |
| `crlf-injection-test.md` | 几乎不交（已收成一行） |
| `csp-bypass-test.md` | 几乎不交（已收成一行）；XSS 走 `xss-test.md` |
| `csrf-test.md` | 专题知识（hack-skills 导入或融合） |
| `csv-formula-injection-test.md` | 几乎不交（已收成一行） |
| `dangling-markup-test.md` | 几乎不交（已收成一行） |
| `dependency-confusion-test.md` | 几乎不交（已收成一行） |
| [deserialization-test.md](deserialization-test.md) | 对象恢复阶段、类型/完整性限制、消费者与链前提 |
| `dns-rebinding-test.md` | 几乎不交（已收成一行）；SSRF 走 `ssrf-test.md` |
| [el-injection-test.md](el-injection-test.md) | 模板/表达式/脚本解释，保存→触发→观察 |
| `email-header-injection-test.md` | 几乎不交（已收成一行） |
| [file-upload-test.md](file-upload-test.md) | 接收→存储→校验→解包/转换→消费；存储与分享案例 |
| `ghost-bits-cast-test.md` | Ghost Bits 原理+常用字+公式；逐字节两套表已砍 |
| `graphql-test.md` | GraphQL（原有+补充） |
| `hpp-test.md` | 几乎不交（已收成一行） |
| `http-host-header-test.md` | 专题知识（hack-skills 导入或融合） |
| `http-smuggling-test.md` | 请求走私（原有+补充） |
| `http2-attacks-test.md` | 几乎不交（已收成一行）；走私走 `http-smuggling-test.md` |
| `idor-test.md` | 越权（中文主线 + 短表指针） |
| `info-leak-test.md` | 信息泄露 |
| [injection-test.md](injection-test.md) | 查询位置、SQL/非 SQL、内容/错误/时间及延迟查询；列表/订阅案例 |
| `insecure-scm-test.md` | 专题知识（hack-skills 导入或融合） |
| `jndi-injection-test.md` | 专题知识（hack-skills 导入或融合） |
| `js-reverse-guide.md` | JS 逆向 |
| `llm-security-test.md` | **禁开越狱教材**（已收成一行）；对话工具走 `agent-tool-exec-test.md` |
| `logic-test.md` | 业务逻辑（支付/流程 + 商家促销绑定） |
| `oauth-jwt-test.md` | OAuth/JWT/SAML/OIDC（原有+多源补充） |
| `open-redirect-test.md` | 专题知识（hack-skills 导入或融合） |
| `path-traversal-lfi-test.md` | 专题知识（hack-skills 导入或融合） |
| `prototype-pollution-test.md` | 专题知识（hack-skills 导入或融合） |
| `race-condition-test.md` | 竞态（原有+补充） |
| `recon-methodology.md` | 侦察方法论 |
| [ssrf-test.md](ssrf-test.md) | 请求能力、逐跳重定向、延迟消费者及受控响应设施；云/代理/回源案例 |
| `subdomain-takeover-test.md` | 专题知识（hack-skills 导入或融合） |
| `type-juggling-test.md` | 专题知识（hack-skills 导入或融合） |
| `waf-bypass.md` | WAF 绕过 |
| `websocket-test.md` | WebSocket（原有+补充） |
| `xslt-injection-test.md` | 几乎不交（已收成一行） |
| `xss-test.md` | XSS（中文开场 + 冷门事件 + XSS→RCE / 自定义协议） |
| `xxe-test.md` | 专题知识（hack-skills 导入或融合） |

**合计：48 个知识文件**（不含本 README）。SRC 报告版式不在本库：见 `rules/vuln-report-format.md`。定级只认 format，本库不定级。
