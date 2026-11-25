package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// 票据 01：oob_generate / oob_poll 两个 worker 工具。
// 会话接缝 oobSession 把 internal/oob 的真实 Interactsh 会话隔离在工具层之下：
// 编排测试用假替身，集成测试（票据 05）用受控 Interactsh 服务。

// OOBInteraction is one callback the OOB service recorded for our probes.
type OOBInteraction struct {
	Protocol     string `json:"protocol"`
	UniqueID     string `json:"probe_id"`
	FullID       string `json:"full_id,omitempty"`
	Remote       string `json:"remote,omitempty"`
	Raw          string `json:"raw,omitempty"`
	TimestampISO string `json:"timestamp,omitempty"`
}

// oobSession is the seam between the tools and the Interactsh client.
type oobSession interface {
	// GenerateContext returns (probeID, canonicalHost) for one fresh callback address.
	GenerateContext(ctx context.Context) (string, string, error)
	// PollContext waits up to `wait` for new interactions, interruptible by ctx.
	PollContext(ctx context.Context, wait time.Duration) ([]OOBInteraction, error)
	checkOpen() error
	pollWindowHealth(since time.Time) error
	Close() error
}

const (
	oobMaxAddresses = 5
	oobDefaultWait  = 5 * time.Second
	oobMaxWait      = 30 * time.Second
)

// oobSeededTools 构造 OOB 工具的「seed 目录壳」：nil 会话版本，只用于
// toolcatalog 读 Name/Description/Schema 入库播种，绝不 Call。
func (t *ToolSet) oobSeededTools() []actool.CoreTool {
	return []actool.CoreTool{t.oobGenerate(nil, nil), t.oobPoll(nil, nil)}
}

// probeRegistry belongs to one assembled run, never to a task or intent that
// may be resumed later. It also serializes tool writes for this run.
type probeRegistry struct {
	gate      chan struct{}
	allocated map[string]struct{}
	pending   []OOBInteraction
	seen      map[string]struct{}
	ignored   int
	runID     string
	window    uint64
}

func (r *probeRegistry) acquire(ctx context.Context) error {
	if r == nil {
		return errNoCompletedPoll
	}
	select {
	case r.gate <- struct{}{}:
		return nil
	default:
	}
	select {
	case r.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *probeRegistry) release() { <-r.gate }

type oobObservation struct {
	Phase           string   `json:"phase"`
	RunID           string   `json:"run_id"`
	ProbeIDs        []string `json:"probe_ids"`
	WindowID        string   `json:"window_id,omitempty"`
	StartedAt       string   `json:"started_at,omitempty"`
	EndedAt         string   `json:"ended_at,omitempty"`
	RequestedWaitMS int64    `json:"requested_wait_ms,omitempty"`
	Complete        bool     `json:"complete"`
}

func (r *probeRegistry) observation(probeID string, wait time.Duration) oobObservation {
	ids := make([]string, 0, len(r.allocated))
	for id := range r.allocated {
		if probeID == "" || probeID == id {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	r.window++
	return oobObservation{
		Phase: "observation", RunID: r.runID, ProbeIDs: ids,
		WindowID:  fmt.Sprintf("%s/%d", r.runID, r.window),
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano), RequestedWaitMS: wait.Milliseconds(),
	}
}

// observe preserves other probes' callbacks while the selected window runs.
// A buffered callback can establish progress, but cannot complete an empty
// observation for another probe. Health covers the entire original window.
func (r *probeRegistry) observe(ctx context.Context, s oobSession, probeID string, wait time.Duration) ([]OOBInteraction, error) {
	start := time.Now()
	deadline := start.Add(wait)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := s.checkOpen(); err != nil {
			return nil, err
		}
		selected := make([]OOBInteraction, 0)
		remaining := make([]OOBInteraction, 0)
		for _, it := range r.pending {
			if probeID == "" || it.UniqueID == probeID {
				selected = append(selected, it)
			} else {
				remaining = append(remaining, it)
			}
		}
		r.pending = remaining
		if len(selected) > 0 {
			return selected, nil
		}
		if time.Now().After(deadline) {
			return selected, s.pollWindowHealth(start)
		}
		its, err := s.PollContext(ctx, wait)
		for _, it := range its {
			if _, owned := r.allocated[it.UniqueID]; !owned {
				r.ignored++
				continue
			}
			key := strings.Join([]string{it.Protocol, it.UniqueID, it.FullID, it.Remote, it.TimestampISO}, "|")
			if _, duplicate := r.seen[key]; duplicate {
				continue
			}
			r.seen[key] = struct{}{}
			r.pending = append(r.pending, it)
		}
		if err != nil {
			return nil, err
		}
		wait = time.Until(deadline)
	}
}

// oobGenerate issues fresh callback addresses. count defaults to 1, max 5.
func (t *ToolSet) oobGenerate(s oobSession, reg *probeRegistry) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "oob_generate",
		Description: "生成本次执行专用的带外（OOB）回调地址（Interactsh）。用于反序列化、SSRF、SSTI/XXE/文件读取等需要带外确认的验证：把回调域名嵌进 payload 发给目标，再用 oob_poll 查是否收到回调。地址仅本 run 有效；一条验证需要多个独立探测时才生成多个，默认 1 个。",
		Schema: obj(map[string]any{
			"count": map[string]any{"type": "integer", "description": "生成个数，默认 1，最多 5"},
		}),
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if err := reg.acquire(ctx); err != nil {
				return jsonResult(map[string]any{"status": "observation_incomplete", "probes": []any{}, "error": err.Error()})
			}
			defer reg.release()
			if err := ctx.Err(); err != nil {
				return jsonResult(map[string]any{"status": "observation_incomplete", "probes": []any{}, "error": err.Error()})
			}
			var a struct {
				Count int `json:"count"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Count < 0 || a.Count > oobMaxAddresses {
				return actool.Errorf(fmt.Sprintf("count 必须在 1–%d 之间（默认 1）", oobMaxAddresses)), nil
			}
			if a.Count == 0 {
				a.Count = 1
			}
			probes := make([]map[string]string, 0, a.Count)
			for i := 0; i < a.Count; i++ {
				id, host, err := s.GenerateContext(ctx)
				if err != nil {
					if errors.Is(err, errSessionClosed) || ctx.Err() != nil {
						return jsonResult(map[string]any{
							"probes": probes, "status": "observation_incomplete", "error": err.Error(),
						})
					}
					out := map[string]any{
						"probes": probes,
						"status": "service_unavailable",
						"error":  err.Error(),
					}
					if saveErr := t.recordOOBUnavailable(err, oobObservation{Phase: "allocation", RunID: reg.runID}); saveErr != nil {
						out["fact_error"] = saveErr.Error()
					}
					return jsonResult(out)
				}
				reg.allocated[id] = struct{}{}
				probes = append(probes, map[string]string{"probe_id": id, "url": host, "domain": host, "http_url": "http://" + host})
			}
			return jsonResult(map[string]any{
				"probes": probes,
				"hint":   "把回调域名嵌入 payload 发送到目标后，用 oob_poll 等待回调；收到回调只是中间证据，仍需按标准卡完成危害取证。",
			})
		},
	})
}

// oobPoll waits (bounded) for OOB callbacks and returns them.
func (t *ToolSet) oobPoll(s oobSession, reg *probeRegistry) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "oob_poll",
		Description: "等待并返回带外回调（配合 oob_generate）。轮询有界等待；只有健康完成的观察窗口才敢下'暂无回调'的结论——服务不可用会明确报 service_unavailable，不要把故障当成目标无漏洞。匹配回调和本轮空窗口会作为带外/否定事实自动写回当前意图；回调只是中间证据，仍需继续验证实际危害，不自动生成 finding 或 severity。",
		Schema: obj(map[string]any{
			"probe_id": str("可选：仅返回指定探测的交互，其他探测交互保留供后续查询"),
			"wait":     map[string]any{"type": "integer", "description": fmt.Sprintf("等待秒数，默认 %d，最多 %d", int(oobDefaultWait.Seconds()), int(oobMaxWait.Seconds()))},
		}),
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if err := reg.acquire(ctx); err != nil {
				return jsonResult(map[string]any{"status": "observation_incomplete", "interactions": []OOBInteraction{}, "error": err.Error()})
			}
			defer reg.release()
			var a struct {
				Wait    int    `json:"wait"`
				ProbeID string `json:"probe_id"`
			}
			_ = json.Unmarshal(in, &a)
			if a.ProbeID != "" {
				if _, ok := reg.allocated[a.ProbeID]; !ok {
					return jsonResult(map[string]any{
						"status": "unknown_probe", "probe_id": a.ProbeID,
						"interactions": []OOBInteraction{},
						"hint":         "该 probe 不属于本次 run；请用 oob_generate 分配新地址，再执行触发动作。",
					})
				}
			}
			if len(reg.allocated) == 0 {
				return jsonResult(map[string]any{
					"status": "observation_incomplete", "interactions": []OOBInteraction{},
					"hint": "本次 run 尚未分配 probe，不能形成有效观察窗口。",
				})
			}
			wait := oobDefaultWait
			if a.Wait > 0 {
				if a.Wait > int(oobMaxWait.Seconds()) {
					return actool.Errorf(fmt.Sprintf("wait 最多 %d 秒", int(oobMaxWait.Seconds()))), nil
				}
				wait = time.Duration(a.Wait) * time.Second
			}
			ignoredBefore := reg.ignored
			observation := reg.observation(a.ProbeID, wait)
			its, err := reg.observe(ctx, s, a.ProbeID, wait)
			observation.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err != nil {
				outcome := "service_unavailable"
				summary := "OOB 服务不可用，本轮未证明目标无漏洞"
				if errors.Is(err, errNoCompletedPoll) || errors.Is(err, errSessionClosed) || ctx.Err() != nil {
					outcome = "observation_incomplete"
					summary = "OOB 观察窗口未完成，不能判断是否有回调"
				}
				out := map[string]any{
					"interactions":         []OOBInteraction{},
					"status":               outcome,
					"error":                err.Error(),
					"ignored_interactions": reg.ignored - ignoredBefore,
					"observation":          observation,
				}
				switch {
				case errors.Is(err, errSessionClosed):
					out["hint"] = "本次 OOB 会话已关闭（run 结束或重启失效），观察窗口未完成；继续验证请用 oob_generate 重新分配回调地址。"
				case outcome == "service_unavailable":
					out["hint"] = "OOB 服务当前不可用，不影响其他验证；如需稳定带外验证可在 config.json 的 oob 块配置自建 Interactsh 服务（server_url + token），或稍后重试。"
				case outcome == "observation_incomplete":
					out["hint"] = "观察窗口内没有完成一次轮询，常由 OOB 服务故障引起；可稍后重试，或配置自建 Interactsh 服务（config.json 的 oob 块）。"
				}
				if id, saveErr := t.recordOOBOutcome(outcome, summary, "", err.Error(), observation); saveErr != nil {
					out["fact_error"] = saveErr.Error()
				} else if id > 0 {
					out["fact_id"] = id
				}
				return jsonResult(out)
			}
			observation.Complete = len(its) == 0
			out := map[string]any{
				"interactions":         its,
				"status":               "ok",
				"count":                strconv.Itoa(len(its)),
				"ignored_interactions": reg.ignored - ignoredBefore,
				"observation":          observation,
			}
			outcome := "no_interaction"
			summary := "OOB 观察窗口内暂无回调（不代表目标无漏洞）"
			detail := fmt.Sprintf("在健康完成的 %s 观察窗口内未收到匹配回调。", wait)
			if len(its) > 0 {
				outcome = "progress"
				summary = fmt.Sprintf("收到 %d 条带外交互（中间证据，尚无最终危害）", len(its))
				detail = oobInteractionDetail(its)
			}
			evidence := ""
			if len(its) > 0 {
				evidence = detail
			}
			if id, saveErr := t.recordOOBOutcome(outcome, summary, detail, evidence, observation); saveErr != nil {
				out["fact_error"] = saveErr.Error()
			} else if id > 0 {
				out["fact_id"] = id
			}
			return jsonResult(out)
		},
	})
}

func oobInteractionDetail(its []OOBInteraction) string {
	parts := make([]string, 0, len(its))
	for _, it := range its {
		part := it.Protocol + " probe=" + it.UniqueID
		if it.Remote != "" {
			part += " remote=" + it.Remote
		}
		if it.TimestampISO != "" {
			part += " at=" + it.TimestampISO
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

func oobToolsForRun(t *ToolSet, s oobSession) []actool.CoreTool {
	if s == nil || t == nil {
		return nil
	}
	runID := t.runInfo.RunID
	if runID == "" { // Standalone tool callers have no Worker invocation.
		runID = rand.Text()
	}
	reg := &probeRegistry{gate: make(chan struct{}, 1), allocated: make(map[string]struct{}), seen: make(map[string]struct{}), runID: runID}
	t.verifyProbe = func(id string) bool {
		if err := reg.acquire(context.Background()); err != nil {
			return false
		}
		defer reg.release()
		_, owned := reg.allocated[id]
		return owned && s.checkOpen() == nil
	}
	return []actool.CoreTool{t.oobGenerate(s, reg), t.oobPoll(s, reg)}
}

// recordOOBOutcome persists one handler-owned route fact while retaining the
// worker's intent. It deliberately stores interaction metadata only: raw
// callback bodies may contain target data or secrets and remain in the trace.
func (t *ToolSet) recordOOBOutcome(outcome, summary, detail, evidence string, observation oobObservation) (int64, error) {
	if t == nil || t.ts == nil || t.ownerNode <= 0 {
		return 0, nil
	}
	payload := map[string]any{
		"intent_id":  t.ownerNode,
		"oob":        observation,
		"summary":    summary,
		"detail":     detail,
		"confidence": "observed",
		"outcome":    outcome,
		"route": map[string]any{
			"outcome": outcome,
		},
	}
	if evidence != "" {
		payload["evidence"] = evidence
	}
	if parent, err := t.ts.GetNode(t.ownerNode); err == nil && parent != nil {
		var pp map[string]any
		if json.Unmarshal(parent.Payload, &pp) == nil {
			if route, ok := pp["route"]; ok {
				payload["route"] = route
				if m, ok := payload["route"].(map[string]any); ok {
					m["outcome"] = outcome
				}
			}
		}
	}
	id, err := t.ts.AddFactForIntent(t.ownerNode, payload, t.worker, nil)
	if err != nil {
		return 0, err
	}
	t.writes.Facts++
	return id, nil
}

func (t *ToolSet) recordOOBUnavailable(err error, observation oobObservation) error {
	if t == nil || t.ts == nil || t.ownerNode <= 0 {
		return nil
	}
	if _, saveErr := t.recordOOBOutcome("service_unavailable", "OOB 服务不可用，本轮未证明目标无漏洞", "", err.Error(), observation); saveErr != nil {
		return saveErr
	}
	return nil
}
