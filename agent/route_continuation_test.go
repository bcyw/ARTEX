package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bcyw/artex/db"
)

func TestRouteRejectsRewordedExecutionWithoutEvidence(t *testing.T) {
	tools := intentTypeToolSet(t)
	first, failed := callIntent(t, tools, map[string]any{
		"summary": "检查自定义导入入口",
		"route":   map[string]any{"entry": "https://example.test/import?url=one", "family": "SSRF", "component": "Custom Parser"},
	})
	if failed {
		t.Fatal(first)
	}
	id := parseCreatedIntentID(t, first)
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	restored := NewToolSet(tools.ts, "planner")
	output, failed := callIntent(t, restored, map[string]any{
		"summary": "换一种 payload 重试",
		"route":   map[string]any{"entry": "https://EXAMPLE.test:443/import?url=two", "family": "ssrf", "component": "custom-parser", "hypothesis": "新说法"},
	})
	if !failed {
		t.Fatalf("无新增证据的换词重试应拒绝：%s", output)
	}
	result, err := restored.graphOverview().Call(t.Context(), json.RawMessage(`{}`), nil)
	if err != nil || result.IsError {
		t.Fatalf("恢复后态势读取失败：%v %s", err, result.Flatten())
	}
}

func TestRouteBudgetCountsContinuationAndMatchesNormalizedIdentity(t *testing.T) {
	tools := intentTypeToolSet(t)
	for i := 0; i < 6; i++ {
		current := map[string]any{
			"entry":     "https://example.test/import?url=one",
			"family":    "ssrf",
			"component": "Custom Parser",
			"tested":    []string{"variant-" + string(rune('1'+i))},
		}
		output, failed := callIntent(t, tools, map[string]any{
			"summary": "第 " + string(rune('一'+i)) + " 次验证",
			"route":   current,
		})
		if failed {
			t.Fatalf("第 %d 次执行被误拒：%s", i+1, output)
		}
		id := parseCreatedIntentID(t, output)
		if err := tools.ts.SetIntentState(id, "done"); err != nil {
			t.Fatal(err)
		}
	}
	output, failed := callIntent(t, tools, map[string]any{
		"summary": "第七次换词",
		"route": map[string]any{
			"entry":     "https://EXAMPLE.test:443/import?url=two",
			"family":    "SSRF",
			"component": "custom-parser",
			"tested":    []string{"variant-7"},
		},
	})
	if !failed || !strings.Contains(output, "6/6") {
		t.Fatalf("第七次带新变体也必须被默认六次预算拦下：%s", output)
	}
}

func TestRouteStopsOnEstablishedImpactAndUsesConfiguredCap(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/upload",
		"family":    "file_upload",
		"component": "custom uploader",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "验证上传链", "route": route})
	if failed {
		t.Fatal(output)
	}
	firstID := parseCreatedIntentID(t, output)
	payload := map[string]any{
		"summary":    "上传链已建立影响",
		"confidence": "observed",
		"route": map[string]any{
			"entry":     "https://example.test/upload",
			"family":    "file_upload",
			"component": "custom uploader",
			"outcome":   "impact",
			"reason":    "webshell 已执行",
		},
	}
	raw, _ := json.Marshal(payload)
	result, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || result.IsError {
		t.Fatalf("记录影响失败：%v %s", err, result.Flatten())
	}
	if err := tools.ts.SetIntentState(firstID, "done"); err != nil {
		t.Fatal(err)
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary": "再换 payload 试试",
		"route": map[string]any{
			"entry":     "https://example.test/upload",
			"family":    "file_upload",
			"component": "custom uploader",
			"next_step": "另一个绕过",
		},
	})
	if !failed || !strings.Contains(output, "已确定停止") {
		t.Fatalf("危害已证实后应提前停止：%s", output)
	}

	oldCap := RouteCapOverride
	SetRouteCapResolver(func() int { return 2 })
	t.Cleanup(func() { RouteCapOverride = oldCap })
	tools = intentTypeToolSet(t)
	for i := 0; i < 2; i++ {
		current := map[string]any{"entry": "https://example.test/api", "family": "sqli", "parameter": "id", "tested": []string{"v" + string(rune('1'+i))}}
		output, failed = callIntent(t, tools, map[string]any{"summary": "SQL 注入验证 " + string(rune('1'+i)), "route": current})
		if failed {
			t.Fatalf("第 %d 次配置范围内应允许：%s", i+1, output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary": "第三次",
		"route":   map[string]any{"entry": "https://example.test/api", "family": "sqli", "parameter": "id", "tested": []string{"v3"}},
	})
	if !failed {
		t.Fatalf("自定义上限 2 应拒绝第三次：%s", output)
	}
}

func TestRouteCapFromIntentPersistsAcrossAttempts(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "ssrf",
		"component": "custom-parser",
	}
	output, failed := callIntent(t, tools, map[string]any{
		"summary":   "自定义路线预算",
		"route":     route,
		"route_cap": 3,
	})
	if failed {
		t.Fatal(output)
	}
	if p := intentPayload(t, tools, parseCreatedIntentID(t, output)); p["route_cap"] != float64(3) {
		t.Fatalf("route_cap 未落库: %#v", p["route_cap"])
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		current := map[string]any{
			"entry":     "https://example.test/import",
			"family":    "ssrf",
			"component": "custom-parser",
			"tested":    []string{"variant-" + string(rune('a'+i))},
		}
		output, failed = callIntent(t, tools, map[string]any{"summary": "继续自定义路线", "route": current})
		if failed {
			t.Fatalf("第 %d 次应在自定义预算内：%s", i+1, output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary": "第三次无预算",
		"route": map[string]any{
			"entry":     "https://example.test/import",
			"family":    "ssrf",
			"component": "custom-parser",
			"tested":    []string{"variant-c"},
		},
	})
	if !failed || !strings.Contains(output, "3/3") {
		t.Fatalf("意图上设置的 route_cap 应持续生效：%s", output)
	}
}

func TestRouteStopsOnPrerequisiteDisprovedAndVariantsExhausted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcome  string
		wantText string
	}{
		{name: "prerequisite_disproved", outcome: "prerequisite_disproved", wantText: "已确定停止"},
		{name: "variants_exhausted", outcome: "variants_exhausted", wantText: "已确定停止"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools := intentTypeToolSet(t)
			route := map[string]any{
				"entry":     "https://example.test/upload",
				"family":    "file_upload",
				"component": "custom uploader",
			}
			output, failed := callIntent(t, tools, map[string]any{"summary": "验证上传链", "route": route})
			if failed {
				t.Fatal(output)
			}
			intentID := parseCreatedIntentID(t, output)
			payload := map[string]any{
				"summary":    "路线结论 " + tc.outcome,
				"confidence": "observed",
				"intent_id":  intentID,
				"route": map[string]any{
					"entry":     "https://example.test/upload",
					"family":    "file_upload",
					"component": "custom uploader",
					"outcome":   tc.outcome,
					"reason":    "验证结论",
				},
			}
			raw, _ := json.Marshal(payload)
			result, err := tools.recordFact().Call(t.Context(), raw, nil)
			if err != nil || result.IsError {
				t.Fatalf("记录路线结论失败：%v %s", err, result.Flatten())
			}
			state := tools.routeStates()[routeIdentity("https://example.test/upload", "file_upload", "custom uploader", "")]
			if state == nil || !state.Stopped {
				t.Fatalf("路线停止状态未从事实恢复: %+v", state)
			}
			if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
				t.Fatal(err)
			}
			output, failed = callIntent(t, tools, map[string]any{
				"summary": "再试一次",
				"route":   route,
			})
			if !failed || !strings.Contains(output, tc.wantText) {
				t.Fatalf("%s 后应停止续探：%s", tc.outcome, output)
			}
		})
	}
}

func TestRouteGlobalControlStopsContinuation(t *testing.T) {
	t.Run("paused", func(t *testing.T) {
		tools := intentTypeToolSet(t)
		route := map[string]any{"entry": "https://example.test/api", "family": "sqli", "parameter": "id"}
		output, failed := callIntent(t, tools, map[string]any{"summary": "暂停前路线", "route": route})
		if failed {
			t.Fatal(output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
		taskID, err := tools.ts.TaskID()
		if err != nil || taskID <= 0 {
			t.Fatalf("读取任务失败: %v", err)
		}
		if err := tools.ts.DB().SetPaused(taskID, true); err != nil {
			t.Fatal(err)
		}
		output, failed = callIntent(t, tools, map[string]any{"summary": "暂停后续探", "route": route})
		if !failed || !strings.Contains(output, "任务已暂停") {
			t.Fatalf("暂停任务应停止路线续探：%s", output)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		tools := intentTypeToolSet(t)
		route := map[string]any{"entry": "https://example.test/api", "family": "sqli", "parameter": "id"}
		output, failed := callIntent(t, tools, map[string]any{"summary": "截止前路线", "route": route})
		if failed {
			t.Fatal(output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
		taskID, err := tools.ts.TaskID()
		if err != nil || taskID <= 0 {
			t.Fatalf("读取任务失败: %v", err)
		}
		past := time.Now().Add(-time.Minute).UTC().Format("2006-01-02 15:04:05.000000+00:00")
		if _, err := tools.ts.DB().Exec(`UPDATE tasks SET deadline_at=$2 WHERE id=$1`, taskID, past); err != nil {
			t.Fatal(err)
		}
		output, failed = callIntent(t, tools, map[string]any{"summary": "截止后续探", "route": route})
		if !failed || !strings.Contains(output, "截止时间") {
			t.Fatalf("过期任务应停止路线续探：%s", output)
		}
	})
}

func TestRouteContinuesAfterOOBEvidenceAndStopsOnThreeInformationFreeRounds(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "ssrf",
		"component": "custom-parser",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "SSRF 路线侦察", "route": route})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	worker := NewToolSet(tools.ts, "worker")
	worker.SetOwnerNode(intentID)
	worker.SetTaskID(tools.taskID)
	session := &fakeSession{url: "nonce.example.test"}
	session.interactions = []OOBInteraction{{Protocol: "dns", UniqueID: "probe-1", Remote: "198.51.100.9"}}
	pollResult, err := worker.oobPoll(session).Call(t.Context(), json.RawMessage(`{"wait":1}`), nil)
	if err != nil || pollResult.IsError {
		t.Fatalf("oob_poll 失败: %v %s", err, pollResult.Flatten())
	}
	oobFactID := int64(decode(t, pollResult.Flatten())["fact_id"].(float64))

	output, failed = callIntent(t, tools, map[string]any{
		"summary":    "根据回调继续 SSRF 验证",
		"parent_ids": []int64{oobFactID},
		"route":      route,
	})
	if failed {
		t.Fatalf("OOB 新事实应允许一次有依据续探：%s", output)
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	output, failed = callIntent(t, tools, map[string]any{"summary": "第四轮没有新信息", "route": route})
	if !failed || !strings.Contains(output, "连续 3 轮") {
		t.Fatalf("三轮无信息应换方向：%s", output)
	}
}

func TestRouteInformationGainResetsInformationFreeRounds(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/graphql",
		"family":    "ssrf",
		"component": "custom-fetcher",
		"tested":    []string{"dns-probe"},
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "第一轮", "route": route})
	if failed {
		t.Fatal(output)
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary": "出现新交互后续探",
		"route": map[string]any{
			"entry":     "https://example.test/graphql",
			"family":    "ssrf",
			"component": "custom-fetcher",
			"tested":    []string{"http-probe"},
			"outcome":   "progress",
		},
	})
	if failed {
		t.Fatalf("新 tested 变体应允许续探并重置无信息计数：%s", output)
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}
	if err := tools.recordRouteRound(); err != nil {
		t.Fatal(err)
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary": "新事实后继续",
		"route": map[string]any{
			"entry":     "https://example.test/graphql",
			"family":    "ssrf",
			"component": "custom-fetcher",
			"tested":    []string{"gopher-probe"},
		},
	})
	if failed {
		t.Fatalf("新信息不应被旧的无信息轮次误伤：%s", output)
	}
}

func TestRouteInformationFreeAccumulatesWithEmptySignature(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":      "https://example.test/report",
		"family":     "ssti",
		"hypothesis": "模板引擎会解析表达式",
		"next_step":  "投递最小表达式",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "初始路线", "route": route})
	if failed {
		t.Fatal(output)
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < routeMaxInformationFree; i++ {
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	state := tools.routeStates()[routeIdentity("https://example.test/report", "ssti", "", "")]
	if state == nil || state.InformationFree < routeMaxInformationFree {
		t.Fatalf("只有假设/下一步的路线也必须累计三轮无信息: %+v", state)
	}
}

func TestRouteInformationFreeCountsPerRoute(t *testing.T) {
	tools := intentTypeToolSet(t)
	routeA := map[string]any{
		"entry":     "https://example.test/a",
		"family":    "ssrf",
		"component": "custom-fetcher",
		"tested":    []string{"a1"},
	}
	routeB := map[string]any{
		"entry":     "https://example.test/b",
		"family":    "ssrf",
		"component": "custom-fetcher",
		"tested":    []string{"b1"},
	}
	for _, route := range []map[string]any{routeA, routeB} {
		output, failed := callIntent(t, tools, map[string]any{"summary": "初始路线", "route": route})
		if failed {
			t.Fatal(output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tools.recordRouteRound(); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"b2", "b3"} {
		output, failed := callIntent(t, tools, map[string]any{
			"summary": "路线 B 新变体 " + variant,
			"route":   map[string]any{"entry": "https://example.test/b", "family": "ssrf", "component": "custom-fetcher", "tested": []string{variant}},
		})
		if failed {
			t.Fatal(output)
		}
		if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
			t.Fatal(err)
		}
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	states := tools.routeStates()
	idA := routeIdentity("https://example.test/a", "ssrf", "custom-fetcher", "")
	idB := routeIdentity("https://example.test/b", "ssrf", "custom-fetcher", "")
	if states[idA] == nil || states[idB] == nil {
		t.Fatalf("路线状态未恢复: %+v", states)
	}
	// 三轮快照里 A 一直未变，累计 3；B 每轮都有新 tested 变体，最后一次
	// 快照虽然与当前相同，但前两轮不同，所以只累计 1。
	if states[idA].InformationFree != 3 {
		t.Fatalf("未变化的路线 A 应独立累计无信息轮次，got %d", states[idA].InformationFree)
	}
	if states[idB].InformationFree != 1 {
		t.Fatalf("持续新增 tested 变体的路线 B 不应累计无信息，got %d", states[idB].InformationFree)
	}
}

func TestRouteInformationIgnoresNonInformativeOOBOutcomes(t *testing.T) {
	for _, outcome := range []string{"no_interaction", "service_unavailable"} {
		if got := routeInformation(&Route{Tested: []string{"dns"}, Outcome: outcome}); got != "tested:dns" {
			t.Fatalf("OOB %s 不应计入路线信息增量，got %q", outcome, got)
		}
	}
	for _, outcome := range []string{"progress", "negative", "blocked"} {
		if got := routeInformation(&Route{Tested: []string{"dns"}, Outcome: outcome}); !strings.Contains(got, "outcome:"+outcome) {
			t.Fatalf("实质性结果 %s 应计入路线信息增量，got %q", outcome, got)
		}
	}
}

func TestRouteSubstantiveFactResetsInformationFree(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "ssrf",
		"component": "custom-fetcher",
		"tested":    []string{"dns-probe"},
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "第一轮", "route": route})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := tools.recordRouteRound(); err != nil {
			t.Fatal(err)
		}
	}
	state := tools.routeStates()[routeIdentity("https://example.test/import", "ssrf", "custom-fetcher", "")]
	if state == nil || state.InformationFree < routeMaxInformationFree {
		t.Fatalf("应已累计无信息轮次: %+v", state)
	}

	raw, _ := json.Marshal(map[string]any{
		"summary":    "收到新的内网响应片段",
		"confidence": "observed",
		"intent_id":  intentID,
		"route": map[string]any{
			"entry":     "https://example.test/import",
			"family":    "ssrf",
			"component": "custom-fetcher",
			"tested":    []string{"dns-probe"},
			"outcome":   "progress",
			"reason":    "响应包含内网 banner",
		},
	})
	result, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || result.IsError {
		t.Fatalf("记录进展事实失败: %v %s", err, result.Flatten())
	}
	state = tools.routeStates()[routeIdentity("https://example.test/import", "ssrf", "custom-fetcher", "")]
	if state == nil || state.InformationFree >= routeMaxInformationFree {
		t.Fatalf("新增实质进展事实应重置无信息计数: %+v", state)
	}
}

func TestRouteContinuationAcceptsFindingAsParentEvidence(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/admin",
		"family":    "auth_bypass",
		"component": "custom session",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "认证绕过路线", "route": route})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	findingID, err := tools.ts.AddNode(db.KindFinding, map[string]any{"summary": "认证绕过已确认", "evidence": "GET /admin -> private fixture", "vulnclass": "测试甲类"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary":    "用 finding 续探同一路线",
		"parent_ids": []int64{findingID},
		"route":      route,
	})
	if failed {
		t.Fatalf("finding 应可作为续探依据：%s", output)
	}
}

func TestRouteStopsWhenTargetTypeCapReached(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/orders",
		"family":    "idor",
		"component": "order-api",
	}
	output, failed := callIntent(t, tools, map[string]any{
		"summary":   "越权路线",
		"vuln_type": "测试甲类",
		"route":     route,
	})
	if failed {
		t.Fatal(output)
	}
	if err := tools.ts.SetIntentState(parseCreatedIntentID(t, output), "done"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := tools.ts.RecordFinding(t.Context(), db.RecordFindingInput{
			TaskID:        tools.taskID,
			ExplorationID: tools.ts.ID(),
			VulnClass:     "测试甲类",
			Severity:      db.SeverityMedium,
			Summary:       "同类上限占用",
		}); err != nil {
			t.Fatal(err)
		}
	}
	output, failed = callIntent(t, tools, map[string]any{
		"summary":   "类型触顶后续探",
		"vuln_type": "测试甲类",
		"route":     route,
	})
	if !failed || !strings.Contains(output, "同类上限") {
		t.Fatalf("既有类型上限应优先于路线续探：%s", output)
	}
}

func TestRouteRecoversFromExistingIntentFacts(t *testing.T) {
	tools := intentTypeToolSet(t)
	routeValue := map[string]any{
		"entry":         "https://example.test/import",
		"family":        "deserialization",
		"component":     "commons-collections 3.2",
		"parameter":     "payload",
		"prerequisites": []string{"gadget class on classpath"},
		"hypothesis":    "ysoserial chain reachable",
		"next_step":     "deliver chain and poll OOB",
		"tested":        []string{"dns gadget"},
		"remaining":     []string{"http gadget"},
	}
	intentID, err := tools.ts.AddIntent(map[string]any{
		"summary":   "既有路线意图",
		"route":     routeValue,
		"route_cap": 4,
	}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	factID, err := tools.ts.AddNode(db.KindFact, map[string]any{
		"summary":    "既有路线事实",
		"confidence": "observed",
		"outcome":    "progress",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.ts.Link(intentID, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}
	restored := NewToolSet(tools.ts, "planner")
	restored.SetTaskID(tools.taskID)
	states := restored.routeStates()
	state := states[routeIdentity("https://example.test/import", "deserialization", "commons-collections 3.2", "payload")]
	if state == nil {
		t.Fatal("路线未从既有意图恢复")
	}
	if state.Intents != 1 || state.Cap != 4 || state.Hypothesis != "ysoserial chain reachable" || state.NextStep != "deliver chain and poll OOB" {
		t.Fatalf("恢复的路线状态不完整: %+v", state)
	}
	if len(state.Prerequisites) != 1 || len(state.Tested) != 1 || len(state.Remaining) != 1 {
		t.Fatalf("恢复的路线结构化字段不完整: %+v", state)
	}
}

func TestRouteRecoveryUsesNewestStateAndDropsTestedRemaining(t *testing.T) {
	tools := intentTypeToolSet(t)
	base := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "deserialization",
		"component": "custom-parser",
	}
	first := map[string]any{
		"entry":      base["entry"],
		"family":     base["family"],
		"component":  base["component"],
		"hypothesis": "旧假设",
		"next_step":  "旧下一步",
		"remaining":  []string{"dns gadget", "http gadget"},
		"tested":     []string{"dns gadget"},
	}
	id, err := tools.ts.AddIntent(map[string]any{"summary": "第一版", "route": first}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.ts.SetIntentState(id, "done"); err != nil {
		t.Fatal(err)
	}
	second := map[string]any{
		"entry":      base["entry"],
		"family":     base["family"],
		"component":  base["component"],
		"hypothesis": "新假设",
		"next_step":  "新下一步",
		"remaining":  []string{"http gadget"},
		"tested":     []string{"dns gadget", "second variant"},
	}
	output, failed := callIntent(t, tools, map[string]any{
		"summary": "第二版",
		"route":   second,
	})
	if failed {
		t.Fatalf("第二条路线意图失败: %s", output)
	}
	state := tools.routeStates()[routeIdentity("https://example.test/import", "deserialization", "custom-parser", "")]
	if state == nil || state.Hypothesis != "新假设" || state.NextStep != "新下一步" {
		t.Fatalf("恢复应取最新意图的假设/下一步: %+v", state)
	}
	remaining := state.RemainingHypotheses()
	if len(remaining) != 1 || remaining[0] != "http gadget" {
		t.Fatalf("已测变体不应继续留在剩余假设: %+v", remaining)
	}
}

func TestRoutePartialFactInheritsParentAndStops(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/upload",
		"family":    "file_upload",
		"component": "custom-uploader",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "上传链", "route": route})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	raw, _ := json.Marshal(map[string]any{
		"summary":    "上传链已证实命令执行",
		"confidence": "observed",
		"intent_id":  intentID,
		"route":      map[string]any{"outcome": "impact"},
	})
	result, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || result.IsError {
		t.Fatalf("记录部分 route 事实失败: %v %s", err, result.Flatten())
	}
	state := tools.routeStates()[routeIdentity("https://example.test/upload", "file_upload", "custom-uploader", "")]
	if state == nil || !state.Stopped || state.Outcome != "impact" {
		t.Fatalf("部分 route 事实应继承父意图身份并停止路线: %+v", state)
	}
}

func TestRouteInferredStopDoesNotCloseRoute(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/upload", "family": "file_upload", "component": "custom-uploader"}
	output, failed := callIntent(t, tools, map[string]any{"summary": "上传链", "route": route})
	if failed {
		t.Fatal(output)
	}
	raw, _ := json.Marshal(map[string]any{
		"summary":    "只探一次，怀疑前置不成立",
		"confidence": "inferred",
		"intent_id":  parseCreatedIntentID(t, output),
		"route":      map[string]any{"outcome": "prerequisite_disproved"},
	})
	result, err := tools.recordFact().Call(t.Context(), raw, nil)
	if err != nil || result.IsError {
		t.Fatalf("记录 inferred 事实失败: %v %s", err, result.Flatten())
	}
	state := tools.routeStates()[routeIdentity("https://example.test/upload", "file_upload", "custom-uploader", "")]
	if state != nil && state.Stopped {
		t.Fatalf("inferred 结论不应硬停止整条路线: %+v", state)
	}
}

func TestContinueIntentCountsRerunsAgainstRouteBudget(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{
		"entry":     "https://example.test/import",
		"family":    "deserialization",
		"component": "custom-parser",
	}
	output, failed := callIntent(t, tools, map[string]any{"summary": "原意图", "route": route})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	initialRun := intentID
	if _, err := tools.ts.AppendActivity(db.Activity{NodeID: &initialRun, Worker: "worker", Kind: "result", Summary: "initial run"}); err != nil {
		t.Fatal(err)
	}
	factID, err := tools.ts.AddNode(db.KindFact, map[string]any{
		"summary":    "首次回调",
		"evidence":   "DNS probe=A",
		"confidence": "observed",
		"outcome":    "progress",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	tools.SetContinueWork(func(intentID int64, msg string) error {
		runs++
		return nil
	})
	call := func(parent int64) (string, bool) {
		raw, _ := json.Marshal(map[string]any{
			"intent_id":  intentID,
			"message":    "用新回调继续",
			"parent_ids": []int64{parent},
			"route":      route,
		})
		res, err := tools.continueIntent().Call(t.Context(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten(), res.IsError
	}
	for i := 0; i < routeDefaultCap-1; i++ {
		if i > 0 {
			next, err := tools.ts.AddNode(db.KindFact, map[string]any{
				"summary":    "新的回调观察 " + string(rune('A'+i)),
				"evidence":   "DNS probe=" + string(rune('A'+i)),
				"confidence": "observed",
				"outcome":    "progress",
			}, 5, "confirmed", "worker", nil)
			if err != nil {
				t.Fatal(err)
			}
			factID = next
		}
		out, failed := call(factID)
		if failed {
			t.Fatalf("第 %d 次续跑应在预算内：%s", i+1, out)
		}
		// Each rerun has finished; mark it done again so the next call is eligible.
		if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
			t.Fatal(err)
		}
	}
	last, err := tools.ts.AddNode(db.KindFact, map[string]any{
		"summary":    "第六次的新回调观察",
		"confidence": "observed",
		"outcome":    "progress",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, failed := call(last)
	if !failed || !strings.Contains(out, "6/6") {
		t.Fatalf("原意图续跑也必须在默认六次上限处停止：%s", out)
	}
	if runs != routeDefaultCap-1 {
		t.Fatalf("达到上限后不得再启动续跑，got %d", runs)
	}
}

func TestContinueIntentRequiresFreshBasis(t *testing.T) {
	tools := intentTypeToolSet(t)
	route := map[string]any{"entry": "https://example.test/import", "family": "ssrf", "component": "custom-fetcher"}
	factID, err := tools.ts.AddNode(db.KindFact, map[string]any{
		"summary":    "可控导入参数",
		"confidence": "observed",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	output, failed := callIntent(t, tools, map[string]any{
		"summary":    "原意图",
		"parent_ids": []int64{factID},
		"route":      route,
	})
	if failed {
		t.Fatal(output)
	}
	intentID := parseCreatedIntentID(t, output)
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	tools.SetContinueWork(func(int64, string) error { return nil })
	call := func(parent int64) (string, bool) {
		raw, _ := json.Marshal(map[string]any{
			"intent_id":  intentID,
			"message":    "续跑",
			"parent_ids": []int64{parent},
			"route":      route,
		})
		res, err := tools.continueIntent().Call(t.Context(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten(), res.IsError
	}
	out, failed := call(factID)
	if !failed || !strings.Contains(out, "没有新增事实") {
		t.Fatalf("重复使用同一依据不得续跑：%s", out)
	}
	nextID, err := tools.ts.AddNode(db.KindFact, map[string]any{
		"summary":    "回调命中",
		"evidence":   "DNS probe=new",
		"confidence": "observed",
		"outcome":    "progress",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tools.ts.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}
	out, failed = call(nextID)
	if failed {
		t.Fatalf("新事实应允许原意图续跑：%s", out)
	}
}
