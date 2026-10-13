# ADR 0003 — own call-graph engine over a per-file IR

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0004 (parsers feed the IR), ADR 0011 (soundness contract)
- **Source:** plan §3.2, §4, §5.4–5.5, risk R2

## Decision

Build **our own demand-driven call-graph engine over a language-neutral
per-file IR, not a wrapper around an existing tool.** Parsers produce the
IR; nothing downstream sees an AST; the analysis consumes only the IR (strict
IR boundary).

- [Jelly](https://github.com/cs-au-dk/jelly) (JS/TS flow-insensitive
  call-graph + vulnerability-exposure analyzer; TypeScript, BSD-3-Clause,
  **Node-only, CLI/server with no documented library API**) is evaluated in
  the M0 spike as a benchmark oracle, run under a pinned Node outside the
  binary. It cannot be the primary engine (Node-only, no public API), but
  its permissively-licensed sources are a design reference for the library
  models (`packages/models`, embedded via `--asset`).
- **Consequence:** this is the main cost and risk (R2): M0 200-line
  call-graph prototype, strict IR boundary, and a scope cut line — v1 ships
  default mode + `--cha`; `--pointer-analysis` (Andersen-style,
  object-sensitive) is stretch M7a.
