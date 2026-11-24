package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordFactExperimentSchemaUpgradePreservesCustomization(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	old, err := pg.GetTool("record_fact")
	if err != nil || old == nil {
		t.Fatal("missing record_fact", err)
	}
	t.Cleanup(func() {
		_ = pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled)
		_ = pg.SetSetting("record_fact_experiment_v1", "false")
	})

	// An old DB: no experiment properties at all, user's own description kept.
	custom := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"summary":{"type":"string"},"custom":{"type":"boolean"}},"required":["summary","custom"]}`)
	if err := pg.UpdateTool("record_fact", "我的自定义说明", custom, json.RawMessage(`["worker"]`), true); err != nil {
		t.Fatal(err)
	}
	_ = pg.SetSetting("record_fact_experiment_v1", "false")
	s.refreshRecordFactExperimentSchema()
	tool, err := pg.GetTool("record_fact")
	if err != nil || tool == nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	if err := json.Unmarshal(tool.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"experiment", "experiments"} {
		if len(schema.Properties[key]) == 0 {
			t.Fatalf("升级后缺少参数 %s: %s", key, tool.Schema)
		}
	}
	if tool.Description != "我的自定义说明" || !tool.Enabled || len(tool.Agents) != 1 {
		t.Fatalf("自定义配置被覆盖: %+v", tool)
	}
	if len(schema.Properties["custom"]) == 0 || strings.Join(schema.Required, ",") != "summary,custom" || schema.AdditionalProperties {
		t.Fatalf("自定义 schema 被覆盖: %s", tool.Schema)
	}
	if !strings.Contains(string(schema.Properties["experiment"]), "execution_state") {
		t.Fatalf("experiment 参数缺少可恢复字段说明: %s", schema.Properties["experiment"])
	}
}
