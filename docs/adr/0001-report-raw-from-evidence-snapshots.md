# 报告中的 raw 报文只取流量证据快照，并做规范化重建

报告需要可直接粘贴进 Burp / Yakit 重放的 raw 请求。抓包库（traffic）可以被删除或归档，按 URL 与时间把发现匹配到抓包记录只是猜测；而 `traffic_evidence_snapshots` 是发现所绑定的请求/响应的不可变副本，带 sha256 与长度校验，独立于抓包生命周期。因此报告的 raw 只从 `findings → finding_traffic_bindings → traffic_evidence_snapshots → evidence blob` 读取；没有绑定的发现只渲染 `evidence.poc` 原文，**不做实时匹配、不回填、不写任何说明**。

重建时做规范化而不是原样回放：统一 CRLF、补齐 `Host`、按实际正文字节重算 `Content-Length`、gzip 正文解压后移除 `Content-Encoding`。原因是从抓包得到的头部用 `\n` 分行、`Content-Length` 可能缺失、压缩体粘进重放器是乱码——原样输出会让"可重放"这个前提直接失效。报告的目的是让人验证漏洞，不是字节级取证。

**Consequences**：绑定开关默认关闭，关闭时报告没有 raw 且不会解释原因；抓包记录的响应起始行是 `HTTP <status>`，报告不伪造协议版本与 reason phrase；无法文本化的二进制正文不输出报文块，也不写占位符（见 ADR-0002）。
