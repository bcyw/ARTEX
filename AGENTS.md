# AGENTS.md

ARTEX is an LLM multi-agent pentest system: a Go backend embeds a Next.js static export; business data uses pure-Go SQLite, without a database service or CGO.

## 交流约定

- 与用户的一切交流使用简体中文：进度说明、提问、方案确认、总结与代码评审意见。
- 代码、标识符、提交信息以及仓库内既有的英文文档保持原样，不因本条规则而翻译。

## Context and boundaries

- Keep Go imports under `github.com/bcyw/artex`; the maintained repository and hardcoded self-update source (`selfupdate/github.go`) are `bcyw/ARTEX`.
- Before domain work, read `GLOSSARY.md` and relevant `docs/adr/` decisions; follow `docs/agents/domain.md` for terminology and ADR conflicts.
- For specs/issues, use the local Markdown tracker in `.scratch/<feature>/`: read `docs/agents/issue-tracker.md`; for triage, read `docs/agents/triage-labels.md` (`Status:` lines, not GitHub labels).
- `.scratch/` is gitignored. Under `docs/`, only `docs/agents/` and `docs/adr/` are unignored; older design references in code may be unavailable.
- Wiring: `cmd/artex/main.go` → `server.Manager` (task/store lifetimes) → `server.Engine` (planner/worker loops); HTTP routes are registered in `server/server.go`.
- The asset graph is global; the exploration graph is task-private, linked through `exploration_anchors`. Code computes asset dedup keys from raw observations. Graph changes wake the planner; workers execute one intent and write facts/findings back.
- `skills/` contains application runtime skills. For `tools/*.yaml` recipes and their strict-argv execution, read `tools/README.md`.
- Production has no Node runtime: dynamic behavior belongs behind Go `/api`, not Next server actions or dynamic route handlers. UI copy is Chinese.

## Development and verification

Go version comes from `go.mod` (currently 1.27.4); CI uses Node.js 22 and Python 3.12. Run npm commands in `web/` using its `package-lock.json`.

```bash
# Install frontend dependencies before starting the dev stack
(cd web && npm ci)
# Backend :8787, recording proxy :8788, Next dev 127.0.0.1:5173
./dev.sh
# Backend only (no embedded UI)
go run ./cmd/artex -addr :8787 -proxy 127.0.0.1:8788

# Backend checks; replace ./server and the regex for a focused package/test
go test ./... -count=1 -timeout 180s
go test ./server -run '^TestExecPython$' -count=1
go vet ./...
go mod verify
go test -race ./server -run '^(TestTerminalTask|TestTimedOutTask|TestRunningTaskAdmission|TestStopTask)' -count=1 -timeout 180s
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

From `web/`:

```bash
npm run typecheck
npm run lint
npm test
node --experimental-strip-types --test tests/navigation.test.ts  # one test file
npm run build:static
```

- Dev `/api` requests proxy to `http://localhost:8787`; override with `AUTOPENTEST_API`. `NEXT_PUBLIC_MOCK=1 npm run dev` previews without a backend.
- `agent`, `db`, `evidence`, and `server` tests isolate SQLite via `internal/testdb`; keep tests away from real `data/`. `TestExecPython` discovers `python3`, skips if absent, or uses the interpreter path in `ARTEX_TEST_PYTHON`.
- Frontend formatting uses Biome (`npm run check:fix`, `npm run format`). `npm run lint` rejects both new errors and resolved debt still listed in `web/lint-baseline.json`; use `npm run lint:baseline` to regenerate and review the diff. `npm run lint:strict` shows all debt.
- After theme CSS changes, run `npm run generate:presets`; it updates the generated section of `web/src/lib/preferences/theme.ts`. `web/.husky/pre-commit` runs this, stages that file, then runs lint-staged.
- For full gates and fresh-DB smoke setup, follow `.github/workflows/ci.yml`: it also runs `govulncheck@v1.9.0`, npm audit, and browser-extension checks. Smoke tests must isolate both `ARTEX_DB_PATH` and `-data`.
- Launcher edits must preserve LF without BOM for shell scripts and ASCII CRLF for `start.bat`; focused check: `python3 -m unittest discover -s scripts -p test_launchers.py -v`.

## Data and standards

- `db/db.go` reapplies `db/schema.sql` plus LLM record/usage schemas at startup and sets `user_version=1`; versions above 1 are rejected. There is no schema migration framework: editing `CREATE TABLE IF NOT EXISTS` does not add columns to existing tables. Plan explicit migration code or a fresh test data directory.
- Queries are native SQLite SQL. `db/sqlite.go` normalizes Go values/results, not PostgreSQL syntax; legacy `pg*` names do not imply a PostgreSQL backend. There is no old PostgreSQL data/config migration path.
- SRC acceptance rules in `standards/src-acceptance.md` are injected independently of DB prompt templates. Its `~~~types` catalog drives planning and reporting (`collect: no` is rejected). When editing it, synchronize `srcAcceptanceDefault` in `agent/srcstandards.go`; that is the fallback when the disk file is missing. Disk edits take effect on the next read.

## Runtime gotchas

- Launch distributed binaries through `start.sh` / `start.bat`: page-driven update/rollback requires their restart-on-exit-75 supervision. `start.sh` does not load `.env`; export variables or use Docker Compose.
- In-page update is disabled for Docker and non-comparable versions such as `dev` or dirty `git describe` output. Docker upgrades use `./update.sh` or `git pull && docker compose up -d --build artex`.
- Config resolution: `ARTEX_CONFIG` → `./config.json` (CWD) → executable directory. `ARTEX_DB_PATH` overrides `database.path`. Under `go run`, `config.BaseDir()` falls back to CWD.
- Runtime data lives in `data/` (SQLite + WAL/SHM, `traffic/`, evidence, archives) and is gitignored. The file manager is confined to `data/workspace/`; keep `ARTEX_DB_PATH` outside it.
- Admin password reset: `./reset-password.sh`; it revokes all existing sessions.
- SSE is same-origin; reverse proxies must disable buffering and use long read timeouts. `NEXT_PUBLIC_SSE_BASE` is baked in at build time.

## Embedded builds and releases

- `npm run build:static` sets `NEXT_EXPORT=1` and creates `web/out/`; plain `npm run build` is not the release export. Copy the **contents** into `server/webui/dist/` before building with `-tags embedui`.
- `./build.sh` handles npm install, static export, `rsync`, and the embedded build; output defaults to `dist/artex-<os>-<arch>/artex` (`.exe` on Windows). Requires `rsync`; packaging also requires `zip`.
- `./build.sh --release` packages five targets plus checksums; narrow it with `ARTEX_TARGETS=linux/amd64 ./build.sh --release`. Set `ARTEX_SKIP_FRONTEND=1` only when `server/webui/dist/` already contains the intended export.
- `scripts/version.sh` resolves `git describe --tags --always --dirty`; override with `ARTEX_BUILD_VERSION`. Plain `go build` leaves `main.version=dev` unless linker flags set it.
- Before pushing a release tag, follow `.github/workflows/release.yml`: tags must be `vMAJOR.MINOR.PATCH[-prerelease]` (no build metadata), with a matching `## [version]` in `CHANGELOG.md` for `scripts/release_notes.py`. Only the highest stable tag promotes `latest`.
