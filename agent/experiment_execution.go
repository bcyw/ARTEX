package agent

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/bcyw/artex/db"
)

// executionProvenance is host metadata on the existing activity row, not a
// second execution log. Completed means the tool returned successfully, never
// that a model's interpretation (or a vulnerability) is proven.
type executionProvenance struct {
	Run       RunInfo `json:"run"`
	Completed bool    `json:"completed"`
}

func activityExecution(a db.Activity) executionProvenance {
	var metadata struct {
		Execution executionProvenance `json:"execution"`
	}
	_ = json.Unmarshal(a.Metadata, &metadata)
	return metadata.Execution
}

func (t *ToolSet) activityProvenance(a db.Activity, ref map[string]any) {
	p := activityExecution(a)
	ref["provenance"] = p
	relation := "unknown"
	if a.Inherited {
		relation = "inherited"
		ref["source_task_id"] = a.SourceTaskID
		ref["inherited"] = true
	} else if p.Run.RunID != "" {
		switch {
		case p.Run.RunID == t.runInfo.RunID && p.Run.IntentID == t.runInfo.IntentID:
			relation = "current_run"
		case p.Run.IntentID == t.runInfo.IntentID:
			relation = "prior_run"
		default:
			relation = "other_intent"
		}
	}
	ref["relation"] = relation
}

func (t *ToolSet) traceProvenance(steps []map[string]any) error {
	for _, step := range steps {
		id, _ := step["step_id"].(int64)
		a, err := t.executionActivity(id)
		if err != nil {
			return err
		}
		if a != nil {
			t.activityProvenance(*a, step)
		}
	}
	return nil
}

func (t *ToolSet) validateExperimentExecution(experiment map[string]any) error {
	// Always replace model-authored provenance, including on unexecuted plans.
	experiment["run"] = t.runInfo
	if err := t.validateExperimentBasis(experiment["execution_basis"], experiment["execution_state"] == "executed" || experiment["discovery"] == "executed"); err != nil {
		return fmt.Errorf("experiment.execution_basis: %w", err)
	}
	if actions, ok := experiment["actions"].([]any); ok {
		for i, raw := range actions {
			action := raw.(map[string]any) // shape checked by validateExperiment
			if err := t.validateExperimentBasis(action["basis"], action["state"] == "executed"); err != nil {
				return fmt.Errorf("experiment.actions[%d].basis: %w", i, err)
			}
		}
	}
	if observation, ok := experiment["observation"].(map[string]any); ok {
		if err := t.validateExperimentBasis(observation["basis"], observation["state"] == "complete"); err != nil {
			return fmt.Errorf("experiment.observation.basis: %w", err)
		}
	}
	return nil
}

func (t *ToolSet) validateExperimentBasis(raw any, completed bool) error {
	if completed {
		return t.validateExecutionBasis(raw)
	}
	if raw == nil {
		return nil
	}
	return t.validateExperimentReferences(map[string]any{"references": []any{raw}})
}

// ActivityByIDs' legacy projection omits Metadata and ToolUseID. Reuse the
// source-aware incremental read for a single row, preserving its read-only gate.
func (t *ToolSet) executionActivity(id int64) (*db.Activity, error) {
	rows, err := t.ts.ActivityByIDsWithSources([]int64{id})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	a := rows[0]
	if a.NodeID == nil {
		return &a, nil
	}
	full, _, err := t.ts.ActivityListWithSources(*a.NodeID, id-1, 1)
	if err != nil {
		return nil, err
	}
	if len(full) == 1 && full[0].ID == id {
		full[0].Detail = a.Detail
		return &full[0], nil
	}
	return nil, nil
}

func (t *ToolSet) validateExecutionBasis(raw any) error {
	basis, ok := raw.(map[string]any)
	if !ok || basis["kind"] != "activity" {
		return fmt.Errorf("需要当前 run 已完成的 activity 工具结果；普通材料不能证明执行")
	}
	if err := t.validateExperimentReferences(map[string]any{"references": []any{basis}}); err != nil {
		return err
	}
	id, ok := basis["id"].(float64)
	if !ok || id <= 0 || id != math.Trunc(id) {
		return fmt.Errorf("activity reference id 无效")
	}
	a, err := t.executionActivity(int64(id))
	if err != nil {
		return err
	}
	var p executionProvenance
	if a != nil {
		p = activityExecution(*a)
	}
	if a == nil || a.Inherited || a.Kind != "tool_result" || a.IsError || a.ToolUseID == "" || !p.Completed ||
		t.runInfo.RunID == "" || p.Run.RunID != t.runInfo.RunID || p.Run.TaskID != t.runInfo.TaskID ||
		p.Run.ExplorationID != t.runInfo.ExplorationID || p.Run.IntentID != t.runInfo.IntentID ||
		a.NodeID == nil || *a.NodeID != t.runInfo.IntentID {
		return fmt.Errorf("activity reference 无法验证为当前 run 的成功执行；请保留 unknown/incomplete 或 blocker")
	}
	basis["verified"] = true
	t.activityProvenance(*a, basis)
	basis["excerpt"] = firstLine(a.Summary, 160)
	return nil
}
