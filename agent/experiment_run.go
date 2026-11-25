package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/db"
)

// experimentRun only joins an actual Call return to its SDK activity event.
// It retains no inputs/results and drains on emission; the existing Activity
// store remains the sole durable execution record.
type experimentRun struct {
	info      RunInfo
	mu        sync.Mutex
	completed map[string]bool
}

func (r *experimentRun) wrap(tools, graphTools []actool.CoreTool) []actool.CoreTool {
	excluded := map[string]bool{"Sleep": true, "TaskOutput": true, "TaskStop": true, "get_tool_execution": true, "wait_tool_execution": true, "cancel_tool_execution": true}
	for _, t := range graphTools {
		excluded[t.Name()] = true
	}
	for i, t := range tools {
		// Allocation, graph reads/writes and asynchronous launch acknowledgements
		// cannot prove an experiment action completed. OOB has its own typed
		// observation semantics; it must opt in through that integration later.
		name := t.Name()
		eligible := !excluded[name] && !strings.HasPrefix(name, "oob_") && !strings.HasPrefix(name, "mcp__") && !strings.HasPrefix(name, "recipe__")
		tools[i] = &experimentTool{CoreTool: t, run: r, eligible: eligible}
	}
	return tools
}

type experimentTool struct {
	actool.CoreTool
	run      *experimentRun
	eligible bool
}

func (t *experimentTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	// A foreground Bash timeout may launch a background task while returning a
	// successful acknowledgement. Use the manager state, never output keywords.
	known := map[string]bool{}
	if tc != nil && tc.Tasks != nil {
		for _, task := range tc.Tasks.List() {
			known[task.ID] = true
		}
	}
	res, err := t.CoreTool.Call(ctx, input, tc)
	completed := t.eligible && err == nil && !res.IsError && ctx.Err() == nil
	if tc != nil && tc.Tasks != nil {
		for _, task := range tc.Tasks.List() {
			if !known[task.ID] {
				completed = false
			}
		}
	}
	if tc != nil && tc.ToolUseID != "" {
		t.run.mu.Lock()
		t.run.completed[tc.ToolUseID] = completed
		t.run.mu.Unlock()
	}
	return res, err
}

func (r *experimentRun) activity(a db.Activity) db.Activity {
	p := executionProvenance{Run: r.info}
	if a.Kind == "tool_result" {
		r.mu.Lock()
		p.Completed = r.completed[a.ToolUseID] && !a.IsError
		delete(r.completed, a.ToolUseID)
		r.mu.Unlock()
	}
	var metadata map[string]any
	_ = json.Unmarshal(a.Metadata, &metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["execution"] = p
	a.Metadata, _ = json.Marshal(metadata)
	return a
}
