# ADR 0016 — engine/policy separation

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0012 (status/verdict semantics the policy consumes), ADR 0007 (CLI front end)
- **Source:** plan §3.15, §4 (`AnalyzerEngine`), §9 (exit-code matrix)

## Decision

**The engine produces a structured `AnalysisResult`; the policy layer maps
it to exit codes; both are tested independently.**

- `AnalyzerEngine.analyze(AnalysisRequest, output, formats, verbose,
  DiagnosticSink)` (JVM ADR 0011 parity) returns **`AnalysisResult`** —
  `findings` (verdicts with evidence, match level, confidence, supply
  path), `completeness` (ADR 0014 states, `unresolvedImports`,
  `dynamicUnscoped`, `opaqueBoundaries`, `graphBuilt`,
  `unlistedInstalled`, `dependencyGraph`), `diagnostics`, `metadata`
  (including `exposure`, `analysisStatus`, `exitReasons[]`, `keys`).
- **The policy layer is a pure function of `AnalysisResult` + flags** —
  defaults preserved (a `PARTIAL` run with no reachable finding exits 0),
  strict opt-ins layered on (`--strict-sources`, `--require-complete`,
  `--fail-on-applicable`, `--opaque-native`, `--malware`); precedence
  `2 > 3 > 1 > 0`; **every triggered condition is listed in
  `exitReasons[]` regardless of the precedence winner** (plan v3.5).
- The same analysis feeds strict CI gates and permissive local triage;
  **reports retain every finding regardless of policy** (`--malware=ignore`
  still lists the finding); the exit-code mapping is tested with every flag
  combination **independent of graph construction** (the §9 matrix).
- `AnalyzerEngine` is the single in-process entry point for the CLI, the
  worker, the GitHub Action, and any future plugin; console I/O is
  abstracted behind the diagnostic sink so all front ends surface identical
  diagnostics with identical exit codes.
