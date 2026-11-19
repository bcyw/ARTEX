# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root, or **`GLOSSARY-MAP.md`** if it exists: it points at one `GLOSSARY.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in.

If any of these don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill creates them lazily when terms or decisions actually get resolved.

`/docs/` is gitignored except for `docs/agents/` and `docs/adr/`, so anything else written under `docs/` stays local to this machine.

## File structure

Single-context repo (the layout this repo uses):

```
/
├── AGENTS.md
├── GLOSSARY.md
├── docs/adr/
├── agent/        ← goals / planner / worker / pentest agents
├── db/           ← asset graph + per-task exploration graph
├── server/       ← /api routes, JWT/SSE, task Manager
├── skills/       ← runtime agent skills
└── web/          ← Next.js static export (UI copy is Chinese)
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders), but worth reopening because…_
