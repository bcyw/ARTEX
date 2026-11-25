package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

// intentNode 构造渲染用的意图节点（只填 renderIntentTask 消费的 ID/Payload）。
func intentNode(id int64, payload string) *db.Node {
	return &db.Node{ID: id, Payload: []byte(payload)}
}

// TestRenderIntentTaskTypeCard 锁带类型意图的任务书：意图原文/意图 id 不变，
// 原文之后追加目录标准卡——规范名、证明物、触发启发式、止损线、纪律齐全。
func TestRenderIntentTaskTypeCard(t *testing.T) {
	render := renderIntentTask(intentNode(42, `{"summary":"探测登录接口注入","asset_ids":[11,12],"vuln_type":"sqli"}`))
	for _, want := range []string{
		`{"summary":"探测登录接口注入","asset_ids":[11,12],"vuln_type":"sqli"}`,
		"意图 id: 42",
		"【本类标准卡",
		"【本方向的漏洞类型】注入类",
		"【拿什么才算数（危害最小证明物）】按实际结果取证",
		"非 SQL 结果不要求数据库名",
		"【触发启发式】适用于输入改变查询、模板、表达式或实体解析语义",
		"【止损线】仅报错、时差、算术回显或 OOB 回调不成立",
		"【纪律】",
		"不得改报其他类型",
		"record_fact",
	} {
		if !strings.Contains(render, want) {
			t.Errorf("带类型任务书缺少 %q\n---\n%s", want, render)
		}
	}
}

// TestRenderIntentTaskNoType 锁纯侦察意图（payload 无 vuln_type）：不加卡，
// 渲染结果与改造前一致。
func TestRenderIntentTaskNoType(t *testing.T) {
	payload := `{"summary":"枚举子域接口","asset_ids":[7]}`
	render := renderIntentTask(intentNode(9, payload))
	if strings.Contains(render, "本类标准卡") || strings.Contains(render, "【触发启发式】") {
		t.Errorf("无类型意图不应出现标准卡\n---\n%s", render)
	}
	if !strings.Contains(render, payload) || !strings.Contains(render, "意图 id: 9") {
		t.Errorf("无类型意图的原文/意图 id 渲染被破坏\n---\n%s", render)
	}
}

// TestRenderIntentTaskProofOverride 锁调用方 proof 优先：意图 payload 自带
// 证明物时用具体的，缺省才回退目录该条 Proof。
func TestRenderIntentTaskProofOverride(t *testing.T) {
	render := renderIntentTask(intentNode(3, `{"summary":"x","vuln_type":"SSRF","proof":"自定义证明物-ABC"}`))
	if !strings.Contains(render, "【拿什么才算数（危害最小证明物）】自定义证明物-ABC") {
		t.Errorf("payload 的 proof 未被优先采用\n---\n%s", render)
	}
	if strings.Contains(render, "服务端发出 + 回显内网数据") {
		t.Errorf("payload 有 proof 时不应再用目录默认 proof\n---\n%s", render)
	}
}

// TestRenderIntentTaskUnknownTypeKeepsOriginal 历史类型已从目录删除时保留任务原文，不加卡。
func TestRenderIntentTaskUnknownTypeKeepsOriginal(t *testing.T) {
	payload := `{"summary":"历史意图","vuln_type":"目录外新类型XYZ"}`
	render := renderIntentTask(intentNode(5, payload))
	if strings.Contains(render, "本类标准卡") || !strings.Contains(render, payload) || !strings.Contains(render, "意图 id: 5") {
		t.Fatalf("未知历史类型应保留原文且不加标准卡: %s", render)
	}
}

// TestRenderIntentTaskMalformedPayload 锁非法 JSON：保持原文渲染、不加卡、不报错。
func TestRenderIntentTaskMalformedPayload(t *testing.T) {
	render := renderIntentTask(intentNode(6, `{"summary":`))
	if strings.Contains(render, "本类标准卡") {
		t.Errorf("非法 payload 不应出现标准卡\n---\n%s", render)
	}
	if !strings.Contains(render, `{"summary":`) || !strings.Contains(render, "意图 id: 6") {
		t.Errorf("非法 payload 的原文渲染被破坏\n---\n%s", render)
	}
}

// TestIntentTypeCardFollowsCatalog 锁卡片文案零硬编码：换一份热载目录，卡片
// 的类型名/证明物/启发式/止损线随之变化（同一意图类型写法不变）。
func TestIntentTypeCardFollowsCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "src-acceptance.md")
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("写临时标准文件: %v", err)
		}
	}
	SrcAcceptancePath(path)
	defer SrcAcceptancePath("")

	write("~~~types\ncap: 3\ntype: 自定义类型甲\ncollect: yes\nproof: 甲类证明物-111\nsignals: 甲类触发-222\nstop: 甲类止损-333\n~~~")
	render := renderIntentTask(intentNode(1, `{"summary":"x","vuln_type":"自定义类型甲"}`))
	for _, want := range []string{"【本方向的漏洞类型】自定义类型甲", "甲类证明物-111", "甲类触发-222", "甲类止损-333"} {
		if !strings.Contains(render, want) {
			t.Errorf("卡片未采用热载目录内容 %q\n---\n%s", want, render)
		}
	}
	if strings.Contains(render, "注入类") {
		t.Errorf("卡片出现了内嵌目录的类型，疑似硬编码\n---\n%s", render)
	}

	// 同一进程内改写热载文件：下一次渲染即采用新目录（不缓存）。
	write("~~~types\ncap: 3\ntype: 自定义类型乙\ncollect: yes\nproof: 乙类证明物-444\nsignals: 乙类触发-555\nstop: 乙类止损-666\n~~~")
	render = renderIntentTask(intentNode(1, `{"summary":"x","vuln_type":"自定义类型乙"}`))
	for _, want := range []string{"【本方向的漏洞类型】自定义类型乙", "乙类证明物-444", "乙类触发-555", "乙类止损-666"} {
		if !strings.Contains(render, want) {
			t.Errorf("热改后卡片未生效 %q\n---\n%s", want, render)
		}
	}
	if strings.Contains(render, "自定义类型甲") {
		t.Errorf("热改后仍渲染旧目录条目\n---\n%s", render)
	}
}
