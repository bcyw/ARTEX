package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/bcyw/artex/db"
	"github.com/bcyw/artex/internal/toolrun"
)

// probeTool reports whether a tool call initiates new external probing — a
// foreground shell command, an HTTP fetch, an OOB allocation, or a deferred
// MCP/recipe tool. It is the single source of truth for the worker finalizer's
// "no new probes during settlement" rule and for any future gates that must
// distinguish probing from read/writeback. experimentRun.wrap keeps its own,
// broader exclusion list because graph reads, launch acknowledgements and
// Sleep are also non-proving there.
func probeTool(name string) bool {
	if name == "Bash" || name == "WebFetch" || name == "oob_generate" {
		return true
	}
	return strings.HasPrefix(name, "mcp__") || strings.HasPrefix(name, "recipe__")
}

func (t *ToolSet) verifyGoal(goal, ev *db.Node) error {
	if ev.State != "confirmed" {
		return fmt.Errorf("evidence must be confirmed; task roots and dismissed nodes are not proof")
	}
	if ev.Kind == db.KindFinding {
		confirmed, err := t.ts.FindingConfirmed(ev.ID)
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("finding evidence must have confirmed status and recorded evidence")
		}
	}
	var g struct {
		VulnClass string   `json:"vulnclass"`
		Coverage  *float64 `json:"coverage_min_pct"`
	}
	if err := json.Unmarshal(goal.Payload, &g); err != nil {
		return fmt.Errorf("invalid goal payload: %w", err)
	}
	if g.Coverage != nil {
		if *g.Coverage < 0 || *g.Coverage > 100 {
			return fmt.Errorf("coverage_min_pct must be between 0 and 100")
		}
		if t.as == nil || t.taskID <= 0 || t.coverageDisabled || !t.as.CoverageEnabled(t.taskID) {
			return fmt.Errorf("coverage verification unavailable or disabled")
		}
		cov, err := t.as.TaskCoverageWithSources(t.taskID)
		if err != nil {
			return fmt.Errorf("coverage lookup: %w", err)
		}
		if cov.Pct == nil {
			return fmt.Errorf("coverage scope has no assets; cannot verify")
		}
		if *cov.Pct*100+1e-9 < *g.Coverage {
			return fmt.Errorf("asset coverage %.2f%% is below required %.2f%%", *cov.Pct*100, *g.Coverage)
		}
	}
	if shellClass(g.VulnClass) {
		var e struct {
			VulnClass string `json:"vulnclass"`
			Evidence  string `json:"evidence"`
		}
		if json.Unmarshal(ev.Payload, &e) != nil || ev.Kind != db.KindFinding || !shellClass(e.VulnClass) || strings.TrimSpace(e.Evidence) == "" {
			return fmt.Errorf("shell goal requires a shell finding with recorded interactive evidence; a fact, RCE or upload alone is insufficient")
		}
	}
	return nil
}

func shellClass(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "getshell", "webshell", "reverse_shell":
		return true
	}
	return false
}

// Recheck proofs at whole-task completion: scope, direct-source links or finding
// triage can change after an earlier goal was marked met.
func (t *ToolSet) allGoalsVerified() (bool, error) {
	met, err := t.ts.GoalsMet()
	if err != nil || !met {
		return false, err
	}
	goals, err := t.ts.ListByKind(db.KindGoal, 10000)
	if err != nil {
		return false, err
	}
	for _, goal := range goals {
		ids, err := t.ts.GoalEvidenceIDs(goal.ID)
		if err != nil {
			return false, err
		}
		valid := false
		for _, id := range ids {
			ev, err := t.ts.GetNodeWithSources(id)
			if err != nil {
				return false, err
			}
			if ev != nil && (ev.Kind == db.KindFact || ev.Kind == db.KindFinding) && t.verifyGoal(goal, ev) == nil {
				valid = true
				break
			}
		}
		if !valid {
			return false, nil
		}
	}
	return len(goals) > 0, nil
}

// A stop check stays inside the SDK loop, so MaxTurns/MaxDuration still apply.
// Never initiate new probes just to satisfy a writeback check.
type workerFinalizer struct {
	base    harness.HookRunner
	tools   *ToolSet
	runs    *toolrun.Manager
	probed  atomic.Bool
	retries int
	failed  bool
}

func (f *workerFinalizer) PreToolUse(ctx context.Context, n string, in []byte) (bool, string, []byte) {
	name := n
	if n == "ExecuteExtraTool" {
		var call struct {
			Name string `json:"tool_name"`
		}
		if json.Unmarshal(in, &call) == nil {
			name = call.Name
		}
	}
	if f.retries > 0 && probeTool(name) {
		return true, "当前正在结束收束，不能发起新探测；请读取已有结果、wait/cancel 或写回具体 blocker", nil
	}
	if f.base != nil {
		return f.base.PreToolUse(ctx, n, in)
	}
	return false, "", nil
}
func (f *workerFinalizer) PostToolUse(ctx context.Context, n string, in, out []byte, isErr bool) {
	if n == "ExecuteExtraTool" {
		var call struct {
			Name string `json:"tool_name"`
		}
		if json.Unmarshal(in, &call) == nil && (strings.HasPrefix(call.Name, "mcp__") || strings.HasPrefix(call.Name, "recipe__")) {
			f.probed.Store(true)
		}
	}
	if probeTool(n) {
		f.probed.Store(true)
	}
	if f.base != nil {
		f.base.PostToolUse(ctx, n, in, out, isErr)
	}
}
func (f *workerFinalizer) Stop(ctx context.Context, msgs []llm.Message) (bool, []string, string) {
	if f.base != nil {
		p, e, m := f.base.Stop(ctx, msgs)
		if p || len(e) > 0 {
			return p, e, m
		}
	}
	if ctx.Err() != nil {
		return false, nil, ""
	}
	if !f.incomplete() {
		return false, nil, ""
	}
	if f.retries >= 2 {
		f.failed = true
		return true, nil, "终态验收未通过：后台工具未收束或探测结论未写回"
	}
	f.retries++
	return false, []string{"结束前请 wait/cancel 尚在运行的工具；用 record_fact 写回本 run、当前 intent 的实验结论或具体 blocker。已执行结论需 experiment.conclusion、成功工具 activity 的 execution_basis 与完整 observation（basis、excerpt）；缺材料时保留 blocked/unknown、incomplete 与具体 blocker。资产、旧 run 结论和自动空 OOB 不能替代当前技术研究结论。不要为凑证据发起新探测，不要编造发现。"}, ""
}

// The SDK skips a repeated stop hook if the model answers a nudge with text
// alone. Worker.Execute also checks this on ReasonCompleted before accepting it.
func (f *workerFinalizer) incomplete() bool {
	if f.runs != nil && f.runs.Pending() > 0 {
		return true
	}
	if f.tools.technicalResearchIntent() {
		return !f.tools.currentRunConclusion()
	}
	return f.probed.Load() && f.tools.Writes().Total() == 0
}

func (t *ToolSet) technicalResearchIntent() bool {
	if t == nil || t.ts == nil || t.ownerNode <= 0 {
		return false
	}
	intent, err := t.ts.GetNode(t.ownerNode)
	if err != nil || intent == nil || intent.Kind != db.KindIntent {
		return false
	}
	p, err := payloadMap(intent.Payload)
	if err != nil {
		return false
	}
	vulnType, _ := p["vuln_type"].(string)
	return strings.TrimSpace(vulnType) != "" || routeIdentityFor(routeFromPayload(p)) != ""
}

func (t *ToolSet) currentRunConclusion() bool {
	// Only a current-owned finding that actually retained evidence qualifies.
	// Legacy-compatible evidence-free writes still count as writes, not completion.
	if t.findingHandoff {
		return true
	}
	ids, err := t.ts.FactsYielded(t.ownerNode)
	if err != nil || t.runInfo.RunID == "" {
		return false
	}
	for _, id := range ids {
		node, err := t.ts.GetNode(id)
		if err != nil || node == nil {
			continue
		}
		p, err := payloadMap(node.Payload)
		if err != nil {
			continue
		}
		for _, e := range factExperiments(p) {
			run := experimentRunInfo(e)
			if run.RunID != t.runInfo.RunID || run.IntentID != t.ownerNode || run.TaskID != t.runInfo.TaskID || run.ExplorationID != t.runInfo.ExplorationID {
				continue
			}
			blocker, _ := e["blocker"].(string)
			if (e["execution_state"] == "blocked" || e["execution_state"] == "unknown") && strings.TrimSpace(blocker) != "" {
				return true
			}
			conclusion, _ := e["conclusion"].(string)
			if strings.TrimSpace(conclusion) != "" && t.supportedObservation(e) != "" {
				return true
			}
		}
	}
	return false
}
