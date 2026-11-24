package server

import (
	"encoding/json"
	"testing"

	"github.com/bcyw/artex/agent"
)

func TestMiningStandardsRouteToolSchemaUpgrade(t *testing.T) {
	s, _ := newRetestServer(t)
	pg := s.m.pg
	oldResolve := agent.ToolResolve
	t.Cleanup(func() { agent.ToolResolve = oldResolve })
	wireTools(pg, nil)
	old, err := pg.GetTool("add_intent")
	if err != nil || old == nil {
		t.Fatalf("tool: %v", err)
	}
	t.Cleanup(func() { _ = pg.UpdateTool(old.Key, old.Description, old.Schema, mustJSON(old.Agents), old.Enabled) })
	var schema map[string]any
	if err := json.Unmarshal(old.Schema, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	delete(props, "priority_reason")
	routeProps := props["route"].(map[string]any)["properties"].(map[string]any)
	delete(routeProps, "priority_basis")
	routeProps["entry"].(map[string]any)["description"] = "custom entry instructions"
	props["priority"].(map[string]any)["default"] = 2
	for _, enabled := range []bool{false, true} {
		if err := pg.UpdateTool("add_intent", "custom description", mustJSON(schema), mustJSON([]string{"planner"}), enabled); err != nil {
			t.Fatal(err)
		}
		_ = pg.SetSetting("route_guidance_tool_schema_v1", "")
		s.seedOrchestrationTools()
		row, err := pg.GetTool("add_intent")
		if err != nil || row == nil {
			t.Fatal(err)
		}
		if row.Enabled != enabled || row.Description != "custom description" || len(row.Agents) != 1 || row.Agents[0] != "planner" {
			t.Fatalf("custom configuration lost: %+v", row)
		}
		var got map[string]any
		if err := json.Unmarshal(row.Schema, &got); err != nil {
			t.Fatal(err)
		}
		p := got["properties"].(map[string]any)
		rp := p["route"].(map[string]any)["properties"].(map[string]any)
		if p["priority_reason"] == nil || rp["priority_basis"] == nil {
			t.Fatal("old database schema missing route priority fields")
		}
		if p["priority"].(map[string]any)["default"] != float64(2) || rp["entry"].(map[string]any)["description"] != "custom entry instructions" {
			t.Fatal("custom schema fields replaced")
		}
	}
	wireTools(pg, nil)
	resolved := names(agent.ToolResolve(t.Context(), "planner", agent.NewToolSet(nil, "").PlannerTools()))["add_intent"]
	if resolved == nil {
		t.Fatal("planner missing add_intent")
	}
	props = resolved.InputSchema()["properties"].(map[string]any)
	if props["priority_reason"] == nil || props["route"].(map[string]any)["properties"].(map[string]any)["priority_basis"] == nil {
		t.Fatal("assembled tool uses stale schema")
	}
}

func TestMiningStandardsPromptReseed(t *testing.T) {
	s, _ := newRetestServer(t)
	s.seedOrchestrationTools()
	defaults := agent.BuiltinPromptSeeds()
	defaults["reporter"] = agent.ReporterDefaultPrompt
	defaults["retester"] = agent.RetesterDefaultPrompt
	for _, tc := range []struct {
		key, flag string
		reseed    func()
	}{
		{"goals", "goals_prompt_src_mining_v5", s.reseedGoalsPrompt},
		{"mainagent", "mainagent_prompt_src_mining_v4", s.reseedMainAgentPrompt},
		{"auto", "auto_prompt_src_mining_v1", s.reseedAutoPrompt},
		{"planner", "planner_prompt_src_mining_v8", s.reseedPlannerPrompt},
		{"worker", "worker_prompt_src_mining_v11", s.reseedWorkerPrompt},
		{"pentest", "pentest_prompt_src_mining_v4", s.reseedPentestPrompt},
		{"reporter", "reporter_prompt_concise_v3", s.reseedReporterPrompt},
		{"retester", "retester_prompt_src_acceptance_v2", s.reseedRetesterPrompt},
	} {
		t.Run(tc.key, func(t *testing.T) {
			a, err := s.m.pg.GetAgentByKey(tc.key)
			if err != nil || a == nil {
				t.Fatalf("missing agent %s: %v", tc.key, err)
			}
			old, err := s.m.pg.CurrentPrompt(a.ID)
			if err != nil {
				t.Fatal(err)
			}
			flag, _, err := s.m.pg.GetSetting(tc.flag)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = s.m.pg.SavePrompt(a.ID, old, "restore fixture", "test")
				_ = s.m.pg.SetSetting(tc.flag, flag)
			})
			if err := s.m.pg.SetSetting(tc.flag, ""); err != nil {
				t.Fatal(err)
			}
			staleVersion, err := s.m.pg.ResetPromptToDefault(a.ID, "STALE PROMPT")
			if err != nil {
				t.Fatal(err)
			}
			tc.reseed()
			got, err := s.m.pg.CurrentPrompt(a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got != defaults[tc.key] {
				t.Fatalf("%s not upgraded to current default", tc.key)
			}
			if got, _, err := s.m.pg.GetSetting(tc.flag); err != nil || got != "true" {
				t.Fatalf("new flag not consumed: %q %v", got, err)
			}
			versions, err := s.m.pg.ListPromptVersions(a.ID)
			if err != nil || len(versions) < 2 || versions[0].Version != staleVersion+1 || versions[1].Template != "STALE PROMPT" {
				t.Fatalf("upgrade did not append a version preserving history: %+v %v", versions, err)
			}
			tc.reseed()
			after, err := s.m.pg.ListPromptVersions(a.ID)
			if err != nil || len(after) != len(versions) {
				t.Fatalf("repeated reseed appended a duplicate version: %v", err)
			}
			if _, err := s.m.pg.SavePrompt(a.ID, "USER CUSTOM PROMPT", "user edit", "test"); err != nil {
				t.Fatal(err)
			}
			tc.reseed()
			got, err = s.m.pg.CurrentPrompt(a.ID)
			if err != nil || got != "USER CUSTOM PROMPT" {
				t.Fatalf("second reseed overwrote customization: %q %v", got, err)
			}
		})
	}
}

func TestMiningStandardsFirstUpgradePreservesCustomPrompt(t *testing.T) {
	s, _ := newRetestServer(t)
	s.seedOrchestrationTools()
	defaults := agent.BuiltinPromptSeeds()
	defaults["reporter"] = agent.ReporterDefaultPrompt
	defaults["retester"] = agent.RetesterDefaultPrompt
	for key, prompt := range defaults {
		a, err := s.m.pg.GetAgentByKey(key)
		if err != nil || a == nil {
			t.Fatalf("agent: %v", err)
		}
		for _, note := range []string{"user edit", "内置默认"} {
			if _, err = s.m.pg.SavePrompt(a.ID, "MY CUSTOM PROMPT", note, "user"); err != nil {
				t.Fatal(err)
			}
			flag := "test_custom_upgrade_" + key + note
			_ = s.m.pg.SetSetting(flag, "")
			s.reseedPromptToDefault(key, flag, prompt, "test")
			got, err := s.m.pg.CurrentPrompt(a.ID)
			if err != nil || got != "MY CUSTOM PROMPT" {
				t.Fatalf("custom overwritten: %q %v", got, err)
			}
		}
	}
}
