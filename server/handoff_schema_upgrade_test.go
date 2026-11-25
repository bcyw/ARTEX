package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/bcyw/artex/agent"
)

// Exact seeded descriptions from 7b8efeb, independent of the upgrade's matcher.
var previousHandoffDescriptions = map[string]struct {
	description string
	properties  map[string]string
}{
	"report_finding": {
		description: "记录确认的漏洞，用 evidence 提供命令输出、日志等可验证证据。description / impact / remediation 按交付报告文体填写：直接描述功能与根因、已验证的影响、可执行的修复，不写工具名、检索过程或“未绑定流量”之类的过程说明。任务上下文传当前 intent_id。返回的 finding_id 是独立漏洞记录 ID，finding_node_id 是探索节点 ID（第一行保留该节点编号）。",
		properties: map[string]string{
			"evidence":  "证据/PoC 文本：精选最能证明漏洞的关键片段（≤20 行），完整请求/响应报文应通过 traffic_refs 绑定流量记录，不在 evidence 里整段倾倒",
			"intent_id": "当前任务的意图 id",
		},
	},
	"record_fact": {
		properties: map[string]string{
			"experiment": "可选的可恢复实验交接：question（待验证问题）、existing_evidence（已有证据）、discovery（static/simulated/executed）、controllable_input、identity（身份/业务状态）、normal_operation（正常操作基线）、variables（声明的变量）、actions（操作序列）、observation（位置/窗口/摘录/state=complete|incomplete|unknown）、execution_state（planned/executed/blocked/unknown）、probe（allocated/send_state=allocated_only|sent|script_unknown|blocked/send_basis）、conclusion、blocker、references（可追溯材料引用）。仅陈述实际可验证状态；模型自填引用不能证明材料存在，未知/未执行不得伪称已执行。",
		},
	},
	"get_worker_trace": {
		description: "查看某条意图(work)的【执行过程】（区别于 get_worker_output 只给最终结论）。三种用法：\n" +
			"① 只传 intent_id → 返回该 work 每一步的摘要流（summary≤100字，含 step_id；只是动作轮廓，不含完整输出）；\n" +
			"② intent_id + q → 只返回命中关键字的步骤摘要（在摘要和完整输出里都搜；仍只给 summary，要看内容用③）；\n" +
			"③ intent_id + step_ids → 返回这些步骤的完整内容(detail)；一次最多取 5 个，超出只返回前 5 个并在 notice/omitted_step_ids 里告知未取的。\n" +
			"典型流程：先①/②定位可疑步骤的 step_id，再用③取其完整输出。不含思考(thinking)步骤。支持直接关联任务的历史 trace；其结果带 source_task_id/inherited=true 且只读。",
	},
}

func TestEvidenceHandoffDescriptionsReachAssembledTools(t *testing.T) {
	s, _ := newRetestServer(t)
	pg := s.m.pg
	oldResolve, oldBinding := agent.ToolResolve, agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolResolve, agent.FindingTrafficBindingEnabled = oldResolve, oldBinding
	})
	wireTools(pg, nil)
	s.seedOrchestrationTools()
	const flag = "evidence_handoff_tool_descriptions_v1"
	previous, _, err := pg.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetSetting(flag, previous) })
	if err := pg.SetSetting(flag, ""); err != nil {
		t.Fatal(err)
	}
	// Simulate an installed database whose earlier upgrades already ran.
	for _, oldFlag := range []string{"tool_schema_refresh_v8_report_skeleton", "record_fact_experiment_v1"} {
		if value, _, err := pg.GetSetting(oldFlag); err != nil || value != "true" {
			t.Fatalf("fixture missing previous upgrade %s: %q %v", oldFlag, value, err)
		}
	}
	wantSchemas := map[string]map[string]any{}
	wantDescriptions := map[string]string{}
	for _, seed := range agent.BuiltinToolSeeds() {
		legacy, ok := previousHandoffDescriptions[seed.Key]
		if !ok {
			continue
		}
		old, err := pg.GetTool(seed.Key)
		if err != nil || old == nil {
			t.Fatalf("missing %s: %v", seed.Key, err)
		}
		t.Cleanup(func() { _ = pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled) })
		var schema map[string]any
		if err := json.Unmarshal(mustJSON(seed.Schema), &schema); err != nil {
			t.Fatal(err)
		}
		// Descriptions may still be built-in while constraints and bindings are
		// user-owned. Replacing the whole schema would silently open this one.
		schema["additionalProperties"] = false
		schema["required"] = []any{"operator_tag"}
		props := schema["properties"].(map[string]any)
		props["operator_tag"] = map[string]any{"type": "string", "enum": []any{"reviewed"}, "description": "custom required input"}
		for property, description := range legacy.properties {
			p := props[property].(map[string]any)
			p["description"] = description
			if p["type"] == "object" {
				p["additionalProperties"] = false
				p["properties"] = map[string]any{"operator_tag": map[string]any{"type": "string"}}
				p["required"] = []any{"operator_tag"}
			} else if property == "evidence" {
				p["maxLength"] = float64(4096)
				p["default"] = "operator-value"
			} else {
				p["default"] = float64(123)
			}
		}
		description := legacy.description
		if description == "" {
			description = "custom parent description"
		}
		if err := pg.UpdateTool(seed.Key, description, mustJSON(schema), mustJSON([]string{"worker"}), true); err != nil {
			t.Fatal(err)
		}
		for property := range legacy.properties {
			props[property].(map[string]any)["description"] = seed.Schema["properties"].(map[string]any)[property].(map[string]any)["description"]
		}
		wantSchemas[seed.Key] = schema
		wantDescriptions[seed.Key] = description
		if legacy.description != "" {
			wantDescriptions[seed.Key] = seed.Desc
		}
	}

	s.seedOrchestrationTools()
	wireTools(pg, nil)
	resolved := names(agent.ToolResolve(t.Context(), "worker", agent.NewToolSet(nil, "").WorkerTools()))
	for key, schema := range wantSchemas {
		tool := resolved[key]
		if tool == nil || tool.Description() != wantDescriptions[key] || !reflect.DeepEqual(tool.InputSchema(), schema) {
			t.Errorf("%s assembled description/schema did not receive the exact default-only upgrade: tool available=%t", key, tool != nil)
		}
		row, err := pg.GetTool(key)
		if err != nil || row == nil || !row.Enabled || !reflect.DeepEqual(row.Agents, []string{"worker"}) {
			t.Errorf("%s changed availability/bindings: %+v %v", key, row, err)
		}
	}
	if value, _, err := pg.GetSetting(flag); err != nil || value != "true" {
		t.Fatalf("description-only upgrade flag not consumed: %q %v", value, err)
	}
}

func TestEvidenceHandoffDescriptionUpgradePreservesCustomization(t *testing.T) {
	s, _ := newRetestServer(t)
	pg := s.m.pg
	oldResolve, oldBinding := agent.ToolResolve, agent.FindingTrafficBindingEnabled
	t.Cleanup(func() {
		agent.ToolResolve, agent.FindingTrafficBindingEnabled = oldResolve, oldBinding
	})
	wireTools(pg, nil)
	s.seedOrchestrationTools()
	const flag = "evidence_handoff_tool_descriptions_v1"
	previous, _, err := pg.GetSetting(flag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.SetSetting(flag, previous) })
	if err := pg.SetSetting(flag, ""); err != nil {
		t.Fatal(err)
	}
	type config struct {
		description string
		schema      map[string]any
		enabled     bool
	}
	want := map[string]config{}
	bindings := []string{"worker", "custom-reviewer"}
	for key, legacy := range previousHandoffDescriptions {
		old, err := pg.GetTool(key)
		if err != nil || old == nil {
			t.Fatalf("missing %s: %v", key, err)
		}
		t.Cleanup(func() { _ = pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled) })
		var schema map[string]any
		if err := json.Unmarshal(old.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		props := schema["properties"].(map[string]any)
		schema["additionalProperties"] = false
		schema["required"] = []any{"local_gate"}
		props["local_gate"] = map[string]any{"type": "boolean", "const": true}
		// A description containing the entire old text is still an operator
		// edit: substring matching must not erase the appended instructions.
		for property, description := range legacy.properties {
			props[property].(map[string]any)["description"] = description + "；用户定制说明"
		}
		description := legacy.description + "；用户定制总说明"
		enabled := key != "report_finding"
		if err := pg.UpdateTool(key, description, mustJSON(schema), mustJSON(bindings), enabled); err != nil {
			t.Fatal(err)
		}
		want[key] = config{description, schema, enabled}
	}

	s.seedOrchestrationTools()
	wireTools(pg, nil)
	resolved := names(agent.ToolResolve(t.Context(), "worker", agent.NewToolSet(nil, "").WorkerTools()))
	for key, expected := range want {
		row, err := pg.GetTool(key)
		if err != nil || row == nil {
			t.Fatalf("missing %s: %v", key, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(row.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if row.Description != expected.description || !reflect.DeepEqual(schema, expected.schema) || row.Enabled != expected.enabled || !reflect.DeepEqual(row.Agents, bindings) {
			t.Errorf("%s custom schema/description/availability changed", key)
		}
		tool := resolved[key]
		if !expected.enabled {
			if tool != nil {
				t.Errorf("%s disabled tool was exposed", key)
			}
		} else if tool == nil || tool.Description() != expected.description || !reflect.DeepEqual(tool.InputSchema(), expected.schema) {
			t.Errorf("%s assembled tool lost customization", key)
		}
	}
	// Once consumed, the dedicated flag must not repeatedly refresh even text
	// the operator deliberately changes back to the former default.
	trace := want["get_worker_trace"]
	legacyTrace := previousHandoffDescriptions["get_worker_trace"].description
	if err := pg.UpdateTool("get_worker_trace", legacyTrace, mustJSON(trace.schema), mustJSON(bindings), true); err != nil {
		t.Fatal(err)
	}
	s.seedOrchestrationTools()
	row, err := pg.GetTool("get_worker_trace")
	if err != nil || row == nil || row.Description != legacyTrace {
		t.Fatalf("description upgrade repeated after its flag was consumed: %v", err)
	}
}
