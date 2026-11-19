package db

import (
	"context"
	"database/sql"
	"encoding/json"
)

// FindingReportSections is the deliverable copy of a finding: what a reviewer
// needs to understand and retest it, as opposed to the agent's working notes.
type FindingReportSections struct {
	Description string
	Impact      string
	Remediation string
	Session     string
}

// TaskReportFinding is a confirmed finding with its report sections and the
// traffic bindings (ordered by position) that supply its reproduction packets.
type TaskReportFinding struct {
	*DBFinding
	Sections FindingReportSections
}

// ListTaskReportFindings returns the confirmed findings of one task, most
// severe first, with bindings attached. Unconfirmed findings are excluded on
// purpose: the report is a deliverable, not a working list.
func (d *DB) ListTaskReportFindings(ctx context.Context, taskID int64) (out []*TaskReportFinding, err error) {
	if taskID <= 0 {
		return nil, nil
	}
	err = d.WithEvidenceReadSnapshot(ctx, func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT f.id, f.task_id, f.node_id, f.vulnclass, COALESCE(f.name, ''), f.severity,
       f.summary, f.evidence, f.worker, f.asset_ids, COALESCE(f.status, 'pending'), f.created_at,
       COALESCE(r.description, ''), COALESCE(r.impact, ''), COALESCE(r.remediation, ''), COALESCE(r.session, '')
FROM findings f
LEFT JOIN finding_report_sections r ON r.finding_id = f.id
WHERE f.task_id = $1 AND f.status = 'confirmed'
ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
         f.created_at DESC`, taskID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			f := &TaskReportFinding{DBFinding: &DBFinding{}}
			var aidsJSON string
			if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Name, &f.Severity,
				&f.Summary, &f.Evidence, &f.Worker, &aidsJSON, &f.Status, &f.CreatedAt,
				&f.Sections.Description, &f.Sections.Impact, &f.Sections.Remediation, &f.Sections.Session); err != nil {
				return err
			}
			_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
			out = append(out, f)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, f := range out {
			ft, err := FindingTrafficTx(tx, f.ID)
			if err != nil {
				return err
			}
			f.TrafficBindings = ft.Bindings
		}
		return nil
	}, nil)
	return out, err
}
