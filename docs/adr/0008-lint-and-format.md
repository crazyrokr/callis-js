# ADR 0008 — lint and format: Biome + strict tsc

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0002 (runtime-agnostic core enables the Node coverage gate)
- **Source:** plan §3.7, §9 (quality gates)

## Decision

**Biome (single binary) plus `tsc --noEmit` with `strict`,
`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`.** This replaces
Checkstyle/SpotBugs from the JVM project.

- The `./check` pipeline (plan §9): `tsc --noEmit` → Biome → tests →
  `tools/coverage-gate.ts` over lcov, with per-directory line-coverage gates
  mirroring the JVM `coverageGate` (`sbom/`, `osv/`, `report/` at 100%;
  `callgraph/` and `verdict/` at ≥ 90%).
- **Branch coverage is unavailable under Bun as far as known**, so the
  branch gate for `callgraph/`/`verdict/` runs as a nightly job with the
  runtime-agnostic core suite under Node with V8 coverage (`c8`) — Bun's
  current capability is confirmed in M0 and the Node job is dropped if it
  exists.
