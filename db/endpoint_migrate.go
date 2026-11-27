package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// migrateEndpoints inventories before rewriting any identities. The smallest
// ID survives; references move before duplicate rows are deleted. Everything,
// including user_version, commits in initialize's single transaction.
func (d *DB) migrateEndpoints(tx *sql.Tx) error {
	columns, err := sqliteColumns(tx, "assets")
	if err != nil {
		return err
	}
	hasServiceID := false
	for _, column := range columns {
		hasServiceID = hasServiceID || column.name == "service_id"
	}
	if !hasServiceID {
		if _, err := tx.Exec(`ALTER TABLE assets ADD COLUMN service_id INTEGER REFERENCES assets(id) ON DELETE SET NULL`); err != nil {
			return err
		}
	}
	if err := migrateHTTPServices(tx); err != nil {
		return err
	}
	raw, _, err := queryJSONRows(tx, `SELECT * FROM assets WHERE type='endpoint' ORDER BY id`)
	if err != nil {
		return err
	}
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return err
	}
	type entry struct {
		id       int64
		identity endpointIdentity
		method   string
		params   string
	}
	groups := map[string][]entry{}
	keys := []string{}
	for _, row := range rows {
		id, _ := jsonInt64(row["id"])
		url, _ := row["url"].(string)
		method, _ := row["method"].(string)
		method = strings.ToUpper(strings.TrimSpace(method))
		identity, identityErr := identifyEndpoint(url)
		paramsRaw, err := json.Marshal(row["params"])
		if err != nil {
			return err
		}
		var params []map[string]any
		if err := json.Unmarshal(paramsRaw, &params); err != nil {
			return fmt.Errorf("asset %d params: %w", id, err)
		}
		paramsJSON, err := endpointParamsJSON(append(identity.Params, params...))
		if err != nil {
			return err
		}
		// Snapshot every legacy row, not just duplicates, so conflicting company,
		// metadata and task-source choices can be traced after a merge.
		row["url"] = endpointObservationURL(url)
		row["params"] = json.RawMessage(paramsJSON)
		links, _, err := queryJSONRows(tx, `SELECT * FROM task_asset_links WHERE asset_id=$1`, id)
		if err != nil {
			return err
		}
		row["task_asset_links"] = links
		snapshot, err := json.Marshal(row)
		if err != nil {
			return err
		}
		outcome := "canonicalized"
		key := identity.URL + "\x00" + method
		if identityErr != nil || method == "" {
			outcome = "retained: unresolved URL or method"
			key = fmt.Sprintf("unresolved:%d", id)
		}
		if len(groups[key]) == 0 {
			keys = append(keys, key)
		} else {
			outcome = "merged"
		}
		groups[key] = append(groups[key], entry{id, identity, method, paramsJSON})
		if _, err := tx.Exec(`INSERT INTO endpoint_migration_audit(legacy_asset_id,canonical_asset_id,outcome,snapshot)
VALUES($1,$2,$3,$4)`, id, groups[key][0].id, outcome, string(snapshot)); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE assets SET params=$2 WHERE id=$1`, id, paramsJSON); err != nil {
			return err
		}
	}
	store := &AssetStore{db: d, company: d.Companies(), tx: tx}
	for _, key := range keys {
		group := groups[key]
		keep := group[0]
		for _, duplicate := range group[1:] {
			if err := mergeLegacyAsset(tx, keep.id, duplicate.id); err != nil {
				return err
			}
		}
		if strings.HasPrefix(key, "unresolved:") {
			continue
		}
		service, err := store.ensureEndpointService(keep.identity.ServiceURL, 0)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE assets SET url=$2, method=$3, service_id=$4 WHERE id=$1`, keep.id, keep.identity.URL, keep.method, service); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE assets SET task_ids=json_array_union(task_ids,(SELECT task_ids FROM assets WHERE id=$2)) WHERE id=$1`, service, keep.id); err != nil {
			return err
		}
	}
	return nil
}

func migrateHTTPServices(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id,url FROM assets WHERE type='service' AND service_type='http' ORDER BY id`)
	if err != nil {
		return err
	}
	type service struct {
		id  int64
		url string
	}
	groups := make(map[string][]service)
	var keys []string
	for rows.Next() {
		var item service
		if err := rows.Scan(&item.id, &item.url); err != nil {
			rows.Close()
			return err
		}
		canonical := canonicalHTTPServiceURL(item.url)
		if canonical == "" {
			canonical = item.url
		}
		if _, ok := groups[canonical]; !ok {
			keys = append(keys, canonical)
		}
		groups[canonical] = append(groups[canonical], item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, canonical := range keys {
		group := groups[canonical]
		keep := group[0]
		for _, duplicate := range group[1:] {
			if err := mergeLegacyAsset(tx, keep.id, duplicate.id); err != nil {
				return fmt.Errorf("merge HTTP service %d into %d: %w", duplicate.id, keep.id, err)
			}
		}
		if _, err := tx.Exec(`UPDATE assets SET url=$2 WHERE id=$1`, keep.id, canonical); err != nil {
			return fmt.Errorf("canonicalize HTTP service %d: %w", keep.id, err)
		}
	}
	return nil
}

func mergeLegacyAsset(tx *sql.Tx, keep, duplicate int64) error {
	if _, err := tx.Exec(`UPDATE assets SET service_id=$1 WHERE service_id=$2`, keep, duplicate); err != nil {
		return fmt.Errorf("remap service references: %w", err)
	}
	for _, stmt := range []string{
		`INSERT INTO exploration_anchors(node_id,asset_id) SELECT node_id,$1 FROM exploration_anchors WHERE asset_id=$2 ON CONFLICT DO NOTHING`,
		`INSERT INTO task_asset_links(task_id,asset_id,source,source_summary,source_node_id,created_at,updated_at)
SELECT task_id,$1,source,source_summary,source_node_id,created_at,updated_at FROM task_asset_links WHERE asset_id=$2
ON CONFLICT(task_id,asset_id) DO UPDATE SET
source=CASE WHEN task_asset_links.source='system' THEN excluded.source ELSE task_asset_links.source END,
source_summary=CASE WHEN task_asset_links.source='system' THEN excluded.source_summary ELSE task_asset_links.source_summary END,
source_node_id=CASE WHEN task_asset_links.source='system' THEN excluded.source_node_id ELSE task_asset_links.source_node_id END`,
		`UPDATE assets AS a SET
params=json_merge_params(a.params,b.params), task_ids=json_array_union(a.task_ids,b.task_ids),
ip=COALESCE(NULLIF(a.ip,''),b.ip), c_segment=COALESCE(NULLIF(a.c_segment,''),b.c_segment),
service_name=COALESCE(NULLIF(a.service_name,''),b.service_name),
status_code=COALESCE(a.status_code,b.status_code), content_length=COALESCE(a.content_length,b.content_length),
page_title=COALESCE(NULLIF(a.page_title,''),b.page_title), favicon_mmh3=COALESCE(NULLIF(a.favicon_mmh3,''),b.favicon_mmh3),
technologies=json_array_union(a.technologies,b.technologies), auth=json_array_union(a.auth,b.auth),
extra=json_merge(b.extra,a.extra),
company_id=CASE WHEN b.company_source='explicit' AND b.company_id IS NOT NULL AND (a.company_source!='explicit' OR a.company_id IS NULL) THEN b.company_id ELSE COALESCE(a.company_id,b.company_id) END,
company_source=CASE WHEN b.company_source='explicit' AND b.company_id IS NOT NULL THEN 'explicit' ELSE a.company_source END,
created_at=CASE WHEN julianday(a.created_at)<julianday(b.created_at) THEN a.created_at ELSE b.created_at END,
last_seen=CASE WHEN julianday(a.last_seen)>julianday(b.last_seen) THEN a.last_seen ELSE b.last_seen END
FROM assets AS b WHERE a.id=$1 AND b.id=$2`,
		`UPDATE endpoint_candidates SET asset_id=$1 WHERE asset_id=$2`,
		`UPDATE findings SET asset_ids=(SELECT json_group_array(DISTINCT CASE WHEN value=$2 THEN $1 ELSE value END) FROM json_each(findings.asset_ids))
WHERE $2 IN (SELECT value FROM json_each(asset_ids))`,
		`UPDATE exploration_nodes SET payload=json_set(payload,'$.asset_ids',json(
	(SELECT json_group_array(DISTINCT CASE WHEN value=$2 THEN $1 ELSE value END) FROM json_each(exploration_nodes.payload,'$.asset_ids'))))
	WHERE json_type(payload,'$.asset_ids')='array' AND $2 IN (SELECT value FROM json_each(payload,'$.asset_ids'))`,
		`DELETE FROM assets WHERE id=$2`,
	} {
		if _, err := tx.Exec(stmt, keep, duplicate); err != nil {
			return fmt.Errorf("merge asset %d into %d: %w", duplicate, keep, err)
		}
	}
	return nil
}
