package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestRouteOperationSchemaUpgradePreservesCustomization(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	pg := s.m.pg
	readCatalog := func() map[string]*db.Tool {
		t.Helper()
		response := request("GET", "/api/tools", "")
		if response.Code != 200 {
			t.Fatalf("read tool catalog: %d %s", response.Code, response.Body.String())
		}
		var body struct {
			Tools []*db.Tool `json:"tools"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		tools := make(map[string]*db.Tool, len(body.Tools))
		for _, tool := range body.Tools {
			tools[tool.Key] = tool
		}
		return tools
	}
	for _, flag := range []string{"route_guidance_tool_schema_v1", "route_operation_tool_schema_v1"} {
		old, _, err := pg.GetSetting(flag)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pg.SetSetting(flag, old) })
	}
	// The old route-guidance upgrade has already run. This release must still
	// upgrade all three tools, including disabled ones and hand-edited schemas.
	if err := pg.SetSetting("route_guidance_tool_schema_v1", "true"); err != nil {
		t.Fatal(err)
	}
	if err := pg.SetSetting("route_operation_tool_schema_v1", "false"); err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		key      string
		property string
		value    json.RawMessage
		enabled  bool
	}{
		{key: "add_intent", enabled: false},
		{key: "continue_intent", property: "method", value: json.RawMessage(`{"type":"string","enum":["POST"],"default":"POST","description":"custom method"}`), enabled: true},
		{key: "record_fact", property: "input_location", value: json.RawMessage(`{"type":"string","pattern":"^body:","description":"custom selector"}`), enabled: false},
	}
	wantSchemas := make(map[string]map[string]any)
	for _, fixture := range fixtures {
		old, err := pg.GetTool(fixture.key)
		if err != nil || old == nil {
			t.Fatalf("missing %s: %v", fixture.key, err)
		}
		t.Cleanup(func() { _ = pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled) })
		var schema map[string]any
		if err := json.Unmarshal([]byte(`{
			"type":"object","description":"custom schema","additionalProperties":false,
			"required":["route","custom"],
			"properties":{
				"custom":{"type":"boolean"},
				"route":{
					"type":"object","description":"custom route","additionalProperties":false,
					"required":["entry"],
					"properties":{"entry":{"type":"string","pattern":"^https://fixture[.]test/","description":"custom entry"}}
				}
			}
		}`), &schema); err != nil {
			t.Fatal(err)
		}
		if fixture.property != "" {
			var field map[string]any
			if err := json.Unmarshal(fixture.value, &field); err != nil {
				t.Fatal(err)
			}
			schema["properties"].(map[string]any)["route"].(map[string]any)["properties"].(map[string]any)[fixture.property] = field
		}
		wantSchemas[fixture.key] = schema
		if err := pg.UpdateTool(fixture.key, "custom "+fixture.key, mustJSON(schema), json.RawMessage(`["worker","custom-agent"]`), fixture.enabled); err != nil {
			t.Fatal(err)
		}
	}

	// Exercise the real startup seeding path rather than calling the migration.
	s = newTestServer(t, s.ctx, s.m, s.skillDir, t.TempDir(), t.TempDir())
	catalog := readCatalog()
	upgraded := make(map[string]*db.Tool)
	for _, fixture := range fixtures {
		tool := catalog[fixture.key]
		if tool == nil {
			t.Fatalf("missing %s after startup", fixture.key)
		}
		upgraded[fixture.key] = tool
		if !tool.System || tool.Description != "custom "+fixture.key || tool.Enabled != fixture.enabled || !reflect.DeepEqual(tool.Agents, []string{"worker", "custom-agent"}) {
			t.Fatalf("%s customization lost: %+v", fixture.key, tool)
		}
		var got map[string]any
		if err := json.Unmarshal(tool.Schema, &got); err != nil {
			t.Fatal(err)
		}
		properties := got["properties"].(map[string]any)["route"].(map[string]any)["properties"].(map[string]any)
		for _, property := range []string{"method", "input_location"} {
			field, ok := properties[property].(map[string]any)
			if !ok || field["type"] != "string" || field["description"] == nil || field["description"] == "" {
				t.Fatalf("%s missing usable route.%s after startup: %s", fixture.key, property, tool.Schema)
			}
			if property != fixture.property {
				delete(properties, property)
			}
		}
		if !reflect.DeepEqual(got, wantSchemas[fixture.key]) {
			t.Fatalf("%s custom schema changed beyond missing fields: %s", fixture.key, tool.Schema)
		}
	}

	// Once upgraded, a later operator edit is authoritative even when it removes
	// the added fields. Another startup must neither reapply nor alter the upgrade.
	upgraded["add_intent"].Schema = mustJSON(wantSchemas["add_intent"])
	tool := upgraded["add_intent"]
	if err := pg.UpdateTool(tool.Key, tool.Description, tool.Schema, mustJSON(tool.Agents), tool.Enabled); err != nil {
		t.Fatal(err)
	}
	newTestServer(t, s.ctx, s.m, s.skillDir, t.TempDir(), t.TempDir())
	catalog = readCatalog()
	for key, want := range upgraded {
		got := catalog[key]
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("repeated startup changed %s: got %+v, want %+v", key, got, want)
		}
	}
}
