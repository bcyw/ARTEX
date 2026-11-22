package db

import "encoding/json"

// RouteRounds returns the latest planner route snapshots, newest first. Route
// state lives in the existing hint payload store so no schema migration is
// needed. Each value is the compact information signature observed in that
// round.
func (s *ExplorationStore) RouteRounds(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT payload FROM exploration_nodes
WHERE exploration_id=$1 AND kind='hint' AND payload->>'kind'='route_round'
ORDER BY id DESC LIMIT $2`, s.expID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p struct {
			Routes map[string]string `json:"routes"`
		}
		if json.Unmarshal(raw, &p) == nil && p.Routes != nil {
			out = append(out, p.Routes)
		}
	}
	return out, rows.Err()
}

// RecordRouteRound persists one planner-visible route snapshot. It is metadata,
// not a new graph kind: existing hint rendering skips entries without human text.
func (s *ExplorationStore) RecordRouteRound(routes map[string]string) error {
	if len(routes) == 0 {
		return nil
	}
	payload, err := json.Marshal(map[string]any{"kind": "route_round", "routes": routes})
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM exploration_nodes
WHERE exploration_id=$1 AND kind='hint' AND payload->>'kind'='route_round'
  AND id NOT IN (
    SELECT id FROM exploration_nodes
    WHERE exploration_id=$1 AND kind='hint' AND payload->>'kind'='route_round'
    ORDER BY id DESC LIMIT 2)`, s.expID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1,'hint',$2,0,'consumed','planner')`, s.expID, string(payload)); err != nil {
		return err
	}
	return tx.Commit()
}

// DB exposes the owning database to read-only stores; the route engine uses it
// only to observe task lifecycle controls.
func (s *ExplorationStore) DB() *DB {
	if s == nil {
		return nil
	}
	return s.db
}
