package agent

import (
	"strings"
	"testing"
)

// TestHuntingFocusGuidanceInjection 锁「挖掘方向」节随收取标准同机制注入
// guidance（票 01：节文本进 agent 提示，七类规范类型名 + 越权 + 触发启发式 +
// 同类上限 + 折叠表 + 可收性×危害优先级说明）。
func TestHuntingFocusGuidanceInjection(t *testing.T) {
	g := findingGuidanceWithStandards("")
	for _, want := range []string{
		"挖掘方向", "可收性 × 危害", "规范类型名", "触发启发式",
		"注入类", "命令执行与反序列化", "SSRF", "认证绕过与账户接管",
		"存储型 XSS", "文件上传 getshell", "业务逻辑",
		"越权", "同类上限", "别名折叠", "自成一桶", "绝不拒收",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guidance 缺少挖掘方向节内容: %q", want)
		}
	}
}
