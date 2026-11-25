package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/bcyw/artex/db"
)

// Ticket 12 uses the published tools and Worker.Execute. The provider is a
// deterministic test double: these checks cover assembly and persistence, not
// real-model judgment or vulnerability discovery effectiveness.
func outcomeCall(t *testing.T, tools []actool.CoreTool, name string, body any) actool.Result {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools {
		if tool.Name() == name {
			res, err := tool.Call(t.Context(), raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
	}
	t.Fatalf("published tool %s missing", name)
	return actool.Result{}
}

func outcomeIntent(t *testing.T, tools *ToolSet, body map[string]any) *db.Node {
	t.Helper()
	res := outcomeCall(t, tools.PlannerTools(), "add_intent", body)
	if res.IsError {
		t.Fatal(res.Flatten())
	}
	intent, err := tools.ts.GetNode(parseCreatedIntentID(t, res.Flatten()))
	if err != nil || intent == nil {
		t.Fatalf("created intent missing: %v", err)
	}
	return intent
}

func outcomeExecute(t *testing.T, tools *ToolSet, intent *db.Node, provider *scriptedProvider) string {
	t.Helper()
	taskID, err := tools.ts.TaskID()
	if err != nil {
		t.Fatal(err)
	}
	start := len(provider.reqs)
	worker := NewWorker(provider, "test-model", t.TempDir(), nil, 0, 8)
	if _, _, err := worker.Execute(t.Context(), "outcome-worker", taskID, nil, tools.ts, intent, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(provider.reqs) <= start {
		t.Fatal("worker did not assemble a request")
	}
	return strings.Join(provider.reqs[start].System, "\n")
}

// Prompt-only and rejection fixtures still hand off their current-run blocker.
func addFixtureBlocker(provider *scriptedProvider, reason string) {
	provider.add(toolTurn("fixture-blocker", "record_fact", map[string]any{
		"summary": reason,
		"experiment": map[string]any{
			"execution_state": "blocked", "blocker": reason,
			"observation": map[string]any{"state": "incomplete"},
		},
	})...)
}

func outcomeCard(t *testing.T, system string) string {
	t.Helper()
	start := strings.Index(system, "【本类标准卡（")
	if start < 0 {
		t.Fatal("worker did not receive its type card")
	}
	return strings.SplitN(system[start:], "【纪律】", 2)[0]
}

func outcomeReport(intentID int64, evidence string) map[string]any {
	return map[string]any{
		"intent_id": intentID, "severity": "medium", "summary": "controlled outcome fixture",
		"description": "输入越过服务端信任边界", "impact": "已核实最小样本的权限影响", "remediation": "在服务端校验权限和输入边界", "evidence": evidence,
	}
}

func outcomeRecorded(t *testing.T, d *db.DB, result string) *db.DBFinding {
	t.Helper()
	parts := strings.SplitN(result, "\n", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "finding recorded: ") {
		t.Fatalf("finding not recorded: %s", result)
	}
	var recorded db.RecordedFinding
	if err := json.Unmarshal([]byte(parts[1]), &recorded); err != nil {
		t.Fatal(err)
	}
	finding, err := d.GetFinding(recorded.FindingID)
	if err != nil || finding == nil {
		t.Fatalf("recorded finding missing: %v", err)
	}
	return finding
}

func TestOutcomeStandardsInjectionProofs(t *testing.T) {
	for _, source := range []string{"embedded", "disk"} {
		t.Run(source, func(t *testing.T) {
			SrcAcceptancePath("")
			if source == "disk" {
				SrcAcceptancePath("../standards/src-acceptance.md")
			}
			t.Cleanup(func() { SrcAcceptancePath("") })
			for _, tc := range []struct {
				alias, proof string
			}{
				{"sqli", "仅 SQL/ORM 查询结果可用库名作为最小样本"},
				{"nosql_injection", "NoSQL/XPath 取实际查询数据"},
				{"ssti", "SSTI/表达式取越过模板或表达式边界的服务端数据/执行实证"},
				{"表达式注入", "SSTI/表达式取越过模板或表达式边界的服务端数据/执行实证"},
				{"xxe", "XXE 取越过实体解析边界的文件内容/内网响应"},
			} {
				t.Run(tc.alias, func(t *testing.T) {
					tools, d := typeAnchorToolSet(t)
					intent := outcomeIntent(t, tools, map[string]any{"summary": "verify applicable outcome", "vuln_type": tc.alias})
					provider := &scriptedProvider{}
					provider.add(toolTurn("report", "report_finding", outcomeReport(intent.ID, "fixture: baseline denied; controlled query returned a private server-side record"))...)
					provider.add(textTurn("reported")...)
					system := outcomeExecute(t, tools, intent, provider)
					if !strings.Contains(outcomeCard(t, system), tc.proof) {
						t.Fatalf("%s worker card lacks applicable proof %q", tc.alias, tc.proof)
					}
					var payload map[string]any
					if err := json.Unmarshal(intent.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					proof, _ := payload["proof"].(string)
					if !strings.Contains(proof, tc.proof) || strings.Contains(proof, "最低共识 = 注出库名") {
						t.Fatalf("intent saved an inapplicable proof: %q", proof)
					}
					finding := outcomeRecorded(t, d, provider.lastToolResult)
					if finding.VulnClass != "注入类" {
						t.Fatalf("typed outcome not persisted: %+v", finding)
					}
				})
			}
		})
	}
}

func TestOutcomeStandardsFileAndData(t *testing.T) {
	for _, source := range []string{"embedded", "disk"} {
		t.Run(source, func(t *testing.T) {
			SrcAcceptancePath("")
			if source == "disk" {
				SrcAcceptancePath("../standards/src-acceptance.md")
			}
			t.Cleanup(func() { SrcAcceptancePath("") })
			for _, tc := range []struct {
				alias, canonical, family string
				card                     []string
			}{
				{"file_read", "任意文件读取", "xxe", []string{"越过路径/权限边界", "非公开服务端文件", "正常可访问文件", "受控标记"}},
				{"file_write", "任意文件写入", "template", []string{"越过预期目录或权限边界", "独立读取或实际加载", "普通上传存储", "清理"}},
				{"数据泄露", "敏感数据泄露", "nosql", []string{"非公开真实业务数据", "敏感字段", "公开性检查", "公开非敏感响应", "受控 A/B"}},
			} {
				t.Run(tc.alias, func(t *testing.T) {
					tools, d := typeAnchorToolSet(t)
					intent := outcomeIntent(t, tools, map[string]any{
						"summary": "verify result-specific proof", "vuln_type": tc.alias,
						"route": map[string]any{"entry": "https://example.test/import", "family": tc.family, "parameter": "document"},
					})
					provider := &scriptedProvider{}
					wrong := outcomeReport(intent.ID, "fixture")
					wrong["vulnclass"] = "SSRF"
					provider.add(toolTurn("wrong", "report_finding", wrong)...)
					provider.add(toolTurn("right", "report_finding", outcomeReport(intent.ID, "fixture: denied baseline; isolated private resource verified after crossing boundary"))...)
					provider.add(textTurn("reported matching outcome")...)
					system := outcomeExecute(t, tools, intent, provider)
					card := outcomeCard(t, system)
					for _, want := range append(tc.card, tc.canonical) {
						if !strings.Contains(card, want) {
							t.Errorf("card missing %q: %s", want, card)
						}
					}
					if !strings.Contains(toolResults(provider.reqs), "类型归属不符") {
						t.Fatal("mismatched result was not rejected")
					}
					finding := outcomeRecorded(t, d, provider.lastToolResult)
					if finding.VulnClass != tc.canonical {
						t.Fatalf("wrong result type persisted: %+v", finding)
					}
					var payload struct {
						VulnType string `json:"vuln_type"`
						Route    struct {
							Family string `json:"family"`
						} `json:"route"`
					}
					if err := json.Unmarshal(intent.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					if payload.VulnType != tc.canonical || payload.Route.Family != tc.family {
						t.Fatalf("mechanism and outcome conflated: %+v", payload)
					}
				})
			}
		})
	}
}

func TestOutcomeStandardsControlledBoundaries(t *testing.T) {
	for _, source := range []string{"embedded", "disk"} {
		t.Run(source, func(t *testing.T) {
			SrcAcceptancePath("")
			if source == "disk" {
				SrcAcceptancePath("../standards/src-acceptance.md")
			}
			t.Cleanup(func() { SrcAcceptancePath("") })
			for _, tc := range []struct {
				typeName, proof string
			}{
				{"越权", "受控 A/B"},
				{"业务逻辑", "业务不变量"},
				{"认证绕过与账户接管", "受控 A/B"},
			} {
				t.Run(tc.typeName, func(t *testing.T) {
					tools, _ := typeAnchorToolSet(t)
					intent := outcomeIntent(t, tools, map[string]any{"summary": "controlled boundary proof", "vuln_type": tc.typeName})
					provider := &scriptedProvider{}
					addFixtureBlocker(provider, "controlled-account fixture is not configured; only inspect its proof requirements")
					provider.add(textTurn("inspect the controlled-account boundary requirements")...)
					system := outcomeExecute(t, tools, intent, provider)
					if !strings.Contains(outcomeCard(t, system), tc.proof) {
						t.Fatalf("controlled boundary absent from card: %s", tc.proof)
					}
					for _, want := range []string{"无需第三方损失", "合法访问自己的数据不成立", "无 exploit", "实际验证证据"} {
						if !strings.Contains(system, want) {
							t.Errorf("assembled discipline missing %q", want)
						}
					}
					for _, stale := range []string{"自己测试数据不算", "自己测试账号的数据 ≠ 漏洞", "只影响自己测试数据不成立", "B 返回空且等于 owner"} {
						if strings.Contains(system, stale) {
							t.Errorf("assembled guidance still rejects valid controlled proof: %q", stale)
						}
					}
				})
			}
		})
	}
}

func TestOutcomeStandardsWorkerIntentOwnership(t *testing.T) {
	SrcAcceptancePath("")
	t.Cleanup(func() { SrcAcceptancePath("") })
	for _, ownerType := range []string{"file_read", ""} {
		t.Run("redirect/"+ownerType, func(t *testing.T) {
			tools, d := typeAnchorToolSet(t)
			owner := outcomeIntent(t, tools, map[string]any{"summary": "assigned result", "vuln_type": ownerType})
			other := outcomeIntent(t, tools, map[string]any{"summary": "another result", "vuln_type": "file_read"})
			provider := &scriptedProvider{}
			addFixtureBlocker(provider, "the supplied evidence belongs to another intent, so the assigned result remains unverified")
			provider.add(toolTurn("redirect", "report_finding", outcomeReport(other.ID, "fixture: alternate intent must not replace the assigned intent"))...)
			provider.add(textTurn("handoff required")...)
			outcomeExecute(t, tools, owner, provider)
			if strings.HasPrefix(provider.lastToolResult, "finding recorded: ") {
				t.Errorf("worker redirected a finding to another intent: %s", provider.lastToolResult)
			}
			findings, _, err := d.ListFindingsPage(db.FindingFilter{TaskID: fmt.Sprint(tools.taskID)}, 1, 10)
			if err != nil || len(findings) != 0 {
				t.Fatalf("rejected redirection persisted a finding: %v %+v", err, findings)
			}
		})
	}
	t.Run("omitted intent inherits owner", func(t *testing.T) {
		tools, d := typeAnchorToolSet(t)
		owner := outcomeIntent(t, tools, map[string]any{"summary": "assigned result", "vuln_type": "file_read"})
		report := outcomeReport(owner.ID, "fixture: isolated private file read with a denied baseline")
		delete(report, "intent_id")
		provider := &scriptedProvider{}
		provider.add(toolTurn("report", "report_finding", report)...)
		provider.add(textTurn("reported")...)
		outcomeExecute(t, tools, owner, provider)
		finding := outcomeRecorded(t, d, provider.lastToolResult)
		if finding.NodeID == nil {
			t.Fatal("finding has no exploration node")
		}
		edges, err := tools.ts.EdgesTouching([]int64{*finding.NodeID})
		if err != nil {
			t.Fatal(err)
		}
		for _, edge := range edges {
			if edge.From == owner.ID && edge.Rel == db.RelYields && edge.To == *finding.NodeID {
				return
			}
		}
		t.Fatalf("omitted intent_id lost the assigned intent lineage: %+v", edges)
	})
}

func TestOutcomeStandardsHotReloadPreservesExplicitProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outcomes.md")
	writeCatalog := func(proof, signal, collect string) {
		t.Helper()
		text := fmt.Sprintf("~~~types\ntype: 可热改结果\ncollect: %s\naliases: hot_outcome\nproof: %s\nsignals: %s\nstop: 缺少受控边界证明只记事实\n~~~\n", collect, proof, signal)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCatalog("旧目录证明物", "旧启发式", "yes")
	SrcAcceptancePath(path)
	t.Cleanup(func() { SrcAcceptancePath("") })
	tools, _ := typeAnchorToolSet(t)
	const explicit = "历史显式 proof：按已保存的私有标记与拒绝基线逐项核实"
	intent := outcomeIntent(t, tools, map[string]any{"summary": "explicit outcome", "vuln_type": "hot_outcome", "proof": explicit})
	original := string(intent.Payload)
	writeCatalog("新目录证明物", "新启发式", "yes")
	provider := &scriptedProvider{}
	addFixtureBlocker(provider, "only catalog assembly is available; no target proof was executed")
	provider.add(textTurn("inspect hot-reloaded card")...)
	system := outcomeExecute(t, tools, intent, provider)
	card := outcomeCard(t, system)
	if !strings.Contains(card, explicit) || !strings.Contains(card, "新启发式") || strings.Contains(card, "新目录证明物") {
		t.Fatal("hot-reloaded card lost the saved proof or retained stale heuristics")
	}
	reloaded, err := tools.ts.GetNode(intent.ID)
	if err != nil || reloaded == nil || string(reloaded.Payload) != original {
		t.Fatalf("hot reload mutated the saved intent: %v %+v", err, reloaded)
	}
	newIntent := outcomeIntent(t, tools, map[string]any{"summary": "new outcome", "vuln_type": "hot_outcome"})
	if payload := intentPayload(t, tools, newIntent.ID); payload["proof"] != "新目录证明物" || payload["vuln_type"] != "可热改结果" {
		t.Fatalf("new intent ignored edited catalog: %+v", payload)
	}
	// The arbitrary catalog name works through both tools; no compiled type table
	// can keep accepting it after its only machine source switches to collect:no.
	writeCatalog("新目录证明物", "新启发式", "no")
	blocked := outcomeCall(t, tools.PlannerTools(), "add_intent", map[string]any{"summary": "blocked outcome", "vuln_type": "hot_outcome"})
	if !blocked.IsError || !strings.Contains(blocked.Flatten(), "缺少受控边界证明") {
		t.Fatalf("collect:no intent was not explicitly rejected: %s", blocked.Flatten())
	}
	provider = &scriptedProvider{}
	addFixtureBlocker(provider, "the result type is now excluded from collection")
	provider.add(toolTurn("blocked", "report_finding", outcomeReport(intent.ID, "fixture"))...)
	provider.add(textTurn("record fact instead")...)
	outcomeExecute(t, tools, intent, provider)
	if strings.HasPrefix(provider.lastToolResult, "finding recorded: ") || !strings.Contains(provider.lastToolResult, "缺少受控边界证明") {
		t.Fatalf("collect:no finding was not explicitly rejected: %s", provider.lastToolResult)
	}
}

func TestOutcomeStandardsChangedResultHandoff(t *testing.T) {
	SrcAcceptancePath("")
	t.Cleanup(func() { SrcAcceptancePath("") })
	tools, d := typeAnchorToolSet(t)
	const proof = "保存的模板 proof：服务端表达式执行的独立可核验结果"
	original := outcomeIntent(t, tools, map[string]any{"summary": "verify template result", "vuln_type": "ssti", "proof": proof})
	provider := &scriptedProvider{}
	report := outcomeReport(original.ID, "fixture: a private marker is readable, not the assigned template outcome")
	report["vulnclass"] = "file_read"
	provider.add(toolTurn("relabel", "report_finding", report)...)
	provider.add(toolTurn("handoff", "record_fact", map[string]any{
		"summary":  "observed a different file-read result",
		"detail":   "isolated private marker matched; planner must create a file-read verification intent",
		"evidence": "fixture baseline denied; marker matched", "confidence": "observed",
		"experiment": map[string]any{"execution_state": "blocked", "blocker": "the assigned template proof remains unverified; the different file-read result needs its own verification intent"},
	})...)
	provider.add(textTurn("handed the changed result to planner")...)
	outcomeExecute(t, tools, original, provider)
	results := toolResults(provider.reqs)
	if !strings.Contains(results, "类型归属不符") || !strings.Contains(results, proof) {
		t.Fatal("relabeling did not retain the original type and explicit proof")
	}
	var factID int64
	if _, err := fmt.Sscanf(provider.lastToolResult, "fact recorded: %d", &factID); err != nil {
		t.Fatalf("changed result did not become a fact: %s", provider.lastToolResult)
	}
	// A subsequent real planner run reads the worker fact before creating the new
	// typed intent. The scripted provider supplies decisions, not production writes.
	planning := &scriptedProvider{}
	planning.add(toolTurn("detail", "node_detail", map[string]any{"id": factID})...)
	planning.add(toolTurn("new-result", "add_intent", map[string]any{
		"summary": "verify the observed file-read boundary", "vuln_type": "file_read", "parent_ids": []int64{factID},
	})...)
	planning.add(textTurn("new typed verification planned")...)
	planner := NewPlanner(planning, "test-model", t.TempDir(), nil, 0, 4)
	if _, _, err := planner.Plan(t.Context(), tools.taskID, nil, tools.ts, "verify observed outcomes", []TriggerEvent{{Kind: "worker_done", IntentID: original.ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toolResults(planning.reqs), "isolated private marker matched") {
		t.Fatal("planner did not recover the result-transition fact")
	}
	newIntent, err := tools.ts.GetNode(parseCreatedIntentID(t, planning.lastToolResult))
	if err != nil || newIntent == nil {
		t.Fatalf("new typed intent missing: %v", err)
	}
	edges, err := tools.ts.EdgesTouching([]int64{factID})
	if err != nil {
		t.Fatal(err)
	}
	yielded, derived := false, false
	for _, edge := range edges {
		yielded = yielded || edge.From == original.ID && edge.Rel == db.RelYields && edge.To == factID
		derived = derived || edge.From == factID && edge.Rel == db.RelDerivedFrom && edge.To == newIntent.ID
	}
	if !yielded || !derived {
		t.Fatalf("result transition lost fact/planner lineage: %+v", edges)
	}
	reloaded, err := tools.ts.GetNode(original.ID)
	if err != nil || reloaded == nil || string(reloaded.Payload) != string(original.Payload) {
		t.Fatal("result transition rewrote the saved original intent")
	}
	verifying := &scriptedProvider{}
	verifying.add(toolTurn("report", "report_finding", outcomeReport(newIntent.ID, "fixture: private marker read confirmed against denied baseline"))...)
	verifying.add(textTurn("verified assigned result")...)
	outcomeExecute(t, tools, newIntent, verifying)
	if finding := outcomeRecorded(t, d, verifying.lastToolResult); finding.VulnClass != "任意文件读取" {
		t.Fatalf("new worker did not retain the new outcome: %+v", finding)
	}
}

func TestOutcomeStandardsWithoutCapture(t *testing.T) {
	oldBinding := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = oldBinding })
	SrcAcceptancePath("")
	t.Cleanup(func() { SrcAcceptancePath("") })
	tools, d := typeAnchorToolSet(t)
	intent := outcomeIntent(t, tools, map[string]any{"summary": "retain local verifiable evidence", "vuln_type": "file_read"})
	path := filepath.Join(t.TempDir(), "private-marker.txt")
	const marker = "ticket12-private-marker-actual-tool-output"
	if err := os.WriteFile(path, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	// Read real local bytes through an execution tool, without a recording proxy,
	// target network, OOB session or model provider. This checks evidence transport,
	// not whether reading this fixture by itself constitutes a vulnerability.
	provider := &scriptedProvider{}
	provider.add(toolTurn("read-evidence", "Read", map[string]any{"file_path": path})...)
	bad := outcomeReport(intent.ID, "Read "+path+": "+marker)
	bad["severity"] = "unverified"
	provider.add(toolTurn("invalid-severity", "report_finding", bad)...)
	provider.add(toolTurn("report", "report_finding", outcomeReport(intent.ID, "Read "+path+": "+marker))...)
	provider.add(textTurn("evidence retained without capture")...)
	system := outcomeExecute(t, tools, intent, provider)
	results := toolResults(provider.reqs)
	if len(provider.reqs) < 2 || !strings.Contains(toolResults(provider.reqs[1:2]), marker) || !strings.Contains(results, "severity 必须为") {
		t.Fatalf("local evidence or severity guard missing: %s", results)
	}
	finding := outcomeRecorded(t, d, provider.lastToolResult)
	if finding.Evidence != "Read "+path+": "+marker || finding.TrafficCount != 0 || finding.Severity != "medium" || !strings.Contains(provider.lastToolResult, `"evidence_status":"not_bound"`) {
		t.Fatalf("capture-off evidence contract changed: %+v %s", finding, provider.lastToolResult)
	}
	for _, want := range []string{"实际验证证据", "无 exploit", "未采集和非 HTTP", "不为补包重复探测"} {
		if !strings.Contains(system, want) {
			t.Errorf("capture-off system lost evidence/severity discipline %q", want)
		}
	}
}

func TestOutcomeStandardsNonHTTPProofContract(t *testing.T) {
	for _, source := range []string{"embedded", "disk"} {
		t.Run(source, func(t *testing.T) {
			SrcAcceptancePath("")
			if source == "disk" {
				SrcAcceptancePath("../standards/src-acceptance.md")
			}
			t.Cleanup(func() { SrcAcceptancePath("") })
			tools, _ := typeAnchorToolSet(t)
			intent := outcomeIntent(t, tools, map[string]any{"summary": "non-HTTP proof", "vuln_type": "file_read"})
			provider := &scriptedProvider{}
			addFixtureBlocker(provider, "non-HTTP target evidence is unavailable; only inspect the proof contract")
			provider.add(textTurn("inspect proof contract")...)
			system := outcomeExecute(t, tools, intent, provider)
			found := false
			for _, line := range strings.Split(system, "\n") {
				if strings.Contains(line, "PoC 可复现") {
					found = true
					if !strings.Contains(line, "验证命令") || !strings.Contains(line, "重放") {
						t.Errorf("replay gate excludes non-HTTP command proof: %s", line)
					}
				}
			}
			if !found {
				t.Fatal("replayable proof gate missing")
			}
		})
	}
}

func TestOutcomeStandardsCaptureOffToolContract(t *testing.T) {
	oldBinding := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return false }
	t.Cleanup(func() { FindingTrafficBindingEnabled = oldBinding })
	tools, _ := typeAnchorToolSet(t)
	intent := outcomeIntent(t, tools, map[string]any{"summary": "capture-off proof", "vuln_type": "file_read"})
	provider := &scriptedProvider{}
	addFixtureBlocker(provider, "capture-off fixture has no target execution; only inspect the assembled tool contract")
	provider.add(textTurn("inspect assembled tool contract")...)
	outcomeExecute(t, tools, intent, provider)
	for _, tool := range provider.reqs[0].Tools {
		if tool.Name != "report_finding" {
			continue
		}
		raw, err := json.Marshal(tool)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"traffic_refs":`) || strings.Contains(string(raw), "完整请求/响应报文应通过 traffic_refs") {
			t.Fatalf("capture-off tool still requires packet binding: %s", raw)
		}
		return
	}
	t.Fatal("worker did not receive report_finding")
}
