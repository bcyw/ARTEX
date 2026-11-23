# AGENTS.md

ARTEX is an LLM multi-agent pentest system: Go embeds a Next.js static export; business data uses pure-Go SQLite (no database service or CGO).

## 交流约定

- 与用户的一切交流使用简体中文：进度说明、提问、方案确认、总结与代码评审意见。
- 代码、标识符、提交信息以及仓库内既有的英文文档保持原样，不因本条规则而翻译。

## Context and boundaries

- Go imports use `github.com/bcyw/artex`; the maintained repository and self-update source (`selfupdate/github.go`) are `bcyw/ARTEX`.
- Before domain work, read `GLOSSARY.md` and relevant `docs/adr/` decisions; follow `docs/agents/domain.md` for terminology and ADR conflicts.
- For specs/issues, read `docs/agents/issue-tracker.md`: tickets live in `.scratch/<feature>/`. For triage, read `docs/agents/triage-labels.md` (`Status:` lines, not GitHub labels).
- `.scratch/` is gitignored. Under `docs/`, only `docs/agents/` and `docs/adr/` are unignored; older design references in code may be unavailable.
- Wiring: `cmd/artex/main.go` → `server.Manager` (task/store lifetimes) → `server.Engine` (planner/worker loops); HTTP routes are registered in `server/server.go`.
- The asset graph is global; each task owns an exploration graph linked through `exploration_anchors`. Graph changes wake the planner; workers execute one intent and write facts/findings back.
- `skills/` contains application runtime skills. For `tools/*.yaml` recipes and their strict-argv execution, read `tools/README.md`.
- The production UI is static, with no Next.js server: dynamic behavior belongs behind Go `/api`. Node may still be used by runtime tools. UI copy is Chinese.

## Development and verification

Use the Go version in `go.mod`; CI uses Node.js 22 and Python 3.12. Run npm commands in `web/` with its `package-lock.json`.

```bash
# Install frontend dependencies before starting the dev stack (from repo root)
(cd web && npm ci)
# Backend :8787, recording proxy :8788, Next dev 127.0.0.1:5173
./dev.sh
# Backend checks; replace ./server and the regex to focus a test
go test ./... -count=1 -timeout 180s
go test ./server -run '^TestExecPython$' -count=1
go vet ./...
go mod verify
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
- `agent`, `db`, `evidence`, and `server` tests isolate SQLite via `internal/testdb`. Smoke runs must set **both** `ARTEX_DB_PATH` and `-data` to temporary locations: `-data` alone does not relocate the business database. See `.github/workflows/ci.yml` for the complete smoke setup.
- `TestExecPython` discovers `python3`, skips if absent, or uses `ARTEX_TEST_PYTHON` as the interpreter path.
- Biome handles formatting (`npm run check:fix`, `npm run format`). `npm run lint` rejects new errors **and resolved debt still in** `web/lint-baseline.json`; after fixing debt, run `npm run lint:baseline` and review the diff.
- After changing theme CSS, run `npm run generate:presets` to update the generated section of `web/src/lib/preferences/theme.ts`. The hook in `web/.husky/pre-commit` also stages that file before lint-staged.
- For task-lifecycle changes, run the focused `go test -race ./server` command in `.github/workflows/ci.yml`. That workflow also defines vulnerability, dependency, and browser-extension gates.
- Launcher edits must preserve LF without BOM for shell scripts and ASCII CRLF for `start.bat`; focused check: `python3 -m unittest discover -s scripts -p test_launchers.py -v`.

## Data and standards

- `db/db.go` reapplies schemas at startup with `user_version=1`, rejecting higher versions. There is no migration framework: changing `CREATE TABLE IF NOT EXISTS` does not alter existing tables. Schema changes need explicit migration code or a fresh test database.
- Queries are native SQLite SQL. `db/sqlite.go` normalizes Go values/results, not PostgreSQL syntax; legacy `pg*` names do not imply PostgreSQL support.
- When editing `standards/src-acceptance.md`, synchronize the fallback `srcAcceptanceDefault` in `agent/srcstandards.go`. Rules are injected independently of DB prompt templates; the `~~~types` catalog drives planning/reporting (`collect: no` is rejected), and disk edits take effect on the next read.

## Runtime gotchas

- Launch distributed binaries through `start.sh` / `start.bat`: page-driven update/rollback requires their restart-on-exit-75 supervision. `start.sh` does not load `.env`; export variables or use Docker Compose.
- For Docker upgrades or password reset, follow `README.md`. In-page update is disabled in Docker and for non-comparable versions such as `dev` or dirty `git describe` output.
- Config resolution: `ARTEX_CONFIG` → `./config.json` (CWD) → executable directory. `ARTEX_DB_PATH` overrides `database.path`. Under `go run`, `config.BaseDir()` falls back to CWD.
- The file manager is confined to `data/workspace/`; keep `ARTEX_DB_PATH` outside it.

## Embedded builds and releases

- Prefer `./build.sh`: it runs `npm ci`, static export, `rsync`, and the embedded Go build. Requires `rsync`; output is `dist/artex-<os>-<arch>/artex` (`.exe` on Windows).
- For manual builds, `npm run build:static` (not `npm run build`) produces `web/out/`. Copy its **contents** with `cp -R web/out/. server/webui/dist/` after creating the destination, then build with `-tags embedui`.
- `./build.sh --release` packages five targets plus checksums (requires `zip`); narrow with `ARTEX_TARGETS=linux/amd64`. Use `ARTEX_SKIP_FRONTEND=1` only when `server/webui/dist/` contains the intended export.
- `scripts/version.sh` resolves `git describe --tags --always --dirty`; override with `ARTEX_BUILD_VERSION`. Plain `go build` leaves `main.version=dev` unless linker flags set it.
- Before tagging, follow `.github/workflows/release.yml`: use `vMAJOR.MINOR.PATCH[-prerelease]` and a matching `## [version]` in `CHANGELOG.md`. Only the highest stable tag promotes `latest`.
