package server

import (
	"encoding/json"
	"log"
)

// seedFindingReportFields adds the deliverable sections to an already-seeded
// report_finding tool. SeedTool is first-insert-only, so without this migration
// existing installs would never see the new parameters. Existing properties,
// descriptions, agent bindings and enabled flags are preserved.
func (s *Server) seedFindingReportFields() {
	const flag = "finding_report_sections_v1"
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	row, err := s.m.pg.GetTool("report_finding")
	if err != nil || row == nil || !row.System {
		return
	}
	var schema map[string]any
	if err = json.Unmarshal(row.Schema, &schema); err != nil || schema == nil {
		log.Printf("[report] upgrade report_finding schema: %v", err)
		return
	}
	props := objectProperty(schema, "properties")
	for name, field := range map[string]any{
		"description": map[string]any{"type": "string", "description": "漏洞描述（交付文体）：功能如何工作、根因、攻击者能做什么；写已验证事实，不写过程旁白"},
		"impact":      map[string]any{"type": "string", "description": "漏洞危害（交付文体）：已验证的数据/权限影响，分条量化"},
		"remediation": map[string]any{"type": "string", "description": "修复建议（交付文体）：可执行的参数级修复，分条"},
		"session":     map[string]any{"type": "string", "description": "可选：测试账号与会话上下文（角色、账号标识、复验用 Cookie/token、账号来源、隔离方式）"},
	} {
		if _, exists := props[name]; !exists {
			props[name] = field
		}
	}
	required, _ := schema["required"].([]any)
	for _, name := range []string{"description", "impact", "remediation"} {
		found := false
		for _, v := range required {
			if v == name {
				found = true
				break
			}
		}
		if !found {
			required = append(required, name)
		}
	}
	schema["required"] = required

	raw, _ := json.Marshal(schema)
	result, err := s.m.pg.Exec(`UPDATE tools SET schema=$2,updated_at=now() WHERE key=$1 AND system AND schema=$3`, "report_finding", string(raw), string(row.Schema))
	if err != nil {
		log.Printf("[report] upgrade report_finding schema: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return // concurrent user edit; retry on next startup
	}
	_ = s.m.pg.SetSetting(flag, "true")
	log.Printf("[report] report_finding 已增加交付报告分节字段(一次性)")
}
