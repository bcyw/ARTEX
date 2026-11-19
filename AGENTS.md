# AGENTS.md

ARTEX is an LLM multi-agent autonomous pentest system: a Go 1.27.4+ backend that serves an embedded Next.js 16 static export, with all business data in an embedded pure-Go SQLite (no CGO, no PostgreSQL).

## 交流约定

- 与用户的一切交流使用简体中文：进度说明、提问、方案确认、总结与代码评审意见。
- 代码、标识符、提交信息以及仓库内既有的英文文档保持原样，不因本条规则而翻译。

## Agent skills

### Issue tracker

Issues and specs live as markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`), recorded as `Status:` lines in issue files. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Repo identity — do not "fix" these

- Go module is `github.com/Autumn-27/artex` even though the maintained repo is `jaykwok/ARTEX`; imports intentionally keep the old path.
- In-page self-update is hardcoded to `jaykwok/ARTEX` in `selfupdate/github.go`. Change it only deliberately.
- This is a self-maintained v1.x fork with a fresh SQLite schema; there is no PostgreSQL data/config migration path.

## Toolchain

Go 1.27.4+, Node.js 22+, Python 3.12, plus `zip`/`rsync` for `build.sh`. SQLite is embedded in the binary — never add a database service.

## Commands

```bash
# Full dev stack: backend :8787, recording proxy :8788, Next dev :5173
./dev.sh
# Backend only (no embedded UI)
go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788

# Go checks (agent/db/evidence/server tests use an isolated temp SQLite DB)
go test ./...
go vet ./...
go test -race ./server -run '^(TestTerminalTask|TestTimedOutTask|TestRunningTaskAdmission|TestStopTask)' -count=1 -timeout 180s
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go mod verify

# Embedded single binary
cd web && npm ci && npm run build:static && cd ..
rsync -a --delete web/out/ server/webui/dist/   # or cp -R web/out/. server/webui/dist/
go build -tags embedui -o artex ./cmd/artex

# Release artifacts (5 targets, zip + SHA256SUMS in dist/)
./build.sh --release
ARTEX_TARGETS=linux/amd64 ./build.sh --release
```

Frontend commands run from `web/`:

```bash
npm ci
npm run typecheck
npm run lint          # baseline gate, see below
npm test              # node --experimental-strip-types --test tests/*.test.ts
npm run build:static  # release export → web/out (sets NEXT_EXPORT=1)
```

- `npm run build` is a plain `next build`, not the release artifact.
- `NEXT_PUBLIC_MOCK=1 npm run dev` renders the UI from mock data with no backend.
- Format/lint with Biome (`npm run check:fix`, `npm run format`), not Prettier/ESLint: 120-column lines, double quotes, trailing commas.

### Lint baseline

`npm run lint` compares Biome errors per file/category/message against `web/lint-baseline.json`. It fails on new errors **and** on baseline entries that became stale. `npm run lint:strict` shows all existing debt. Regenerate the baseline only with `npm run lint:baseline` and review its JSON diff.

`web/.husky/pre-commit` regenerates `src/lib/preferences/theme.ts`, stages it, then runs lint-staged; bypassing it leaves generated theme metadata stale.

### Script tests and CI order

```bash
python -m unittest discover -s scripts -p 'test_*.py' -v
```

CI enforces that Unix shell scripts are LF without BOM and `start.bat` is ASCII CRLF. Full CI order: `go test` → `go vet` → race subset → `govulncheck` → `npm ci && typecheck && lint && test && npm audit --audit-level=low && build:static` → Python tests → browser-extension `node --check`/`node --test` → build with `-tags embedui` and smoke `/api/health` against a temporary `ARTEX_DB_PATH`.

## Layout

- `cmd/artex/main.go` — flags `-addr`, `-proxy`, `-data`, `-reset-password`; startup and self-update bootstrap.
- `server/` — `net/http` routes registered in `server/server.go` (Go method patterns), JWT/SSE, `Manager` (task/store lifetimes), `Engine` (planner loop + workers, timeouts).
- `agent/` — goals/planner/worker/mainagent/pentest/retester/auto agents on the `norma` SDK; tools expose the two graphs.
- `db/` — both graphs plus business data; embedded `db/schema.sql`.
- Support packages: `traffic/` MITM recorder, `intercept/` + `guard/` approval gate, `enrich/` async DNS/HTTP completion, `llmpool/` LLM failover, `llmrec/` request recording, `mcphttp/` remote MCP, `notify/`, `report/`, `evidence/`, `selfupdate/`.
- `web/src/app` — App Router; `@/*` alias maps to `web/src/*`; UI copy is Chinese.
- `skills/` runtime agent skills; `tools/*.yaml` strict-argv tool recipes (see `tools/README.md`).
- `standards/src-acceptance.md` SRC 漏洞收取标准（黑名单/证据线/定级纪律）。启动时读入注入到能产出 finding 的 agent 提示（代码固定段，不受 DB 模板影响）；黑名单同时在 `agent/srcstandards.go` 的 `SrcFindingBlocked` 做入库硬闸（命中且无「升级证据」→ `findings.status='quarantined'` 隔离区，不进交付报告）。改口径直接改该文件即可，无需重编译。

### Dual graph

A global asset graph (`assets`, `companies`, `task_scope`) is shared across tasks; each task has a private exploration graph (`exploration_nodes` + anchors + activity). `exploration_anchors` links the two. The program computes asset dedup keys — agents only submit raw observations. The engine is event-driven: graph changes wake the planner, which dispatches intents; workers execute one intent and write facts/findings back.

## SQLite schema

`db/schema.sql` plus the `llm_records` and `llm_usage` schemas are executed on every startup, then `PRAGMA user_version=1`. There is **no migration framework and no `ALTER TABLE` path**: adding a column to an existing table requires explicit migration code or a fresh data directory. Startup refuses a DB whose `user_version > 1`. Built-in agents and intercept rules are seeded during initialization.

## Runtime gotchas

- `start.sh` / `start.bat` is the supported entrypoint: it supervises `artex` and relaunches on exit code 75 for page-driven update/rollback. Running `./artex` directly breaks that flow; `-h` is fine.
- In-page update is disabled for `dev` or dirty `git describe` builds, and for Docker (`ARTEX_VERSION` defaults to `dev`). Docker upgrades use `./update.sh` or `git pull && docker compose up -d --build artex`.
- `start.sh` does **not** read `.env`; export env vars yourself, or use Docker Compose (`ARTEX_UPDATE_GITHUB_TOKEN`, `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, `ARTEX_LLM_*`).
- Config resolution: `ARTEX_CONFIG` → `./config.json` (CWD) → executable directory. `ARTEX_DB_PATH` overrides `database.path`. Under `go run`, `config.BaseDir()` falls back to CWD.
- Runtime data lives in `data/` (SQLite + WAL/SHM, `traffic/`, evidence, archives) and is gitignored. The file manager is confined to `data/workspace/`; keep `ARTEX_DB_PATH` outside it.
- Tests: `agent`, `db`, `evidence`, and `server` use `internal/testdb`, which points `ARTEX_DB_PATH` at a per-package temp dir; tests must never touch `data/`. `TestExecPython` skips without `python3`; set `ARTEX_TEST_PYTHON` to run it.
- Admin password reset: `./reset-password.sh` (or pipe to `./artex -reset-password`); it revokes all existing sessions.
- SSE is same-origin; reverse proxies must disable buffering and use long read timeouts. `NEXT_PUBLIC_SSE_BASE` is baked in at build time.
- Frontend output is a pure static export with no Node runtime in production: do not add server actions or dynamic route handlers; put dynamic behavior behind the Go `/api`.
- Code comments reference `docs/...` design documents that are gitignored and absent from the repo — infer behavior from code instead of looking for them.

## Release

- Tags must match `vMAJOR.MINOR.PATCH[-prerelease]` (no build metadata). Pushing `v*` runs CI, cross-builds five targets, packages the browser extension, pushes GHCR images, and creates the GitHub Release.
- `scripts/release_notes.py` requires a matching `## [x.y.z]` section in `CHANGELOG.md`, or the release job fails; add the changelog entry with the version bump.
- `build.sh` derives the version from `git describe --tags --always --dirty`; set `ARTEX_BUILD_VERSION` for reproducible clean builds.
