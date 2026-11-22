package server

import (
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestMiningStandardsPromptReseed(t *testing.T) {
	s, _ := newRetestServer(t)
	for _, tc := range []struct {
		key, flag string
		reseed    func()
	}{
		{"goals", "goals_prompt_src_mining_v4", s.reseedGoalsPrompt},
		{"mainagent", "mainagent_prompt_src_mining_v3", s.reseedMainAgentPrompt},
		{"planner", "planner_prompt_src_mining_v6", s.reseedPlannerPrompt},
		{"worker", "worker_prompt_src_mining_v8", s.reseedWorkerPrompt},
		{"pentest", "pentest_prompt_src_mining_v3", s.reseedPentestPrompt},
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
			if _, err := s.m.pg.SavePrompt(a.ID, "STALE PROMPT", "fixture", "test"); err != nil {
				t.Fatal(err)
			}
			tc.reseed()
			got, err := s.m.pg.CurrentPrompt(a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got != agent.BuiltinPromptSeeds()[tc.key] {
				t.Fatalf("%s not upgraded to current default", tc.key)
			}
			if got, _, err := s.m.pg.GetSetting(tc.flag); err != nil || got != "true" {
				t.Fatalf("new flag not consumed: %q %v", got, err)
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
