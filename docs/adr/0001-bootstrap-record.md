# ADR 0001 — M0 bootstrap record and ADR index

- **Status:** accepted (2026-10-13, plan v3.6); M0 fills in the measurement
  results as it progresses.
- **Convention:** 0002–0017 each hold one decision of plan §3; future changes
  amend the specific decision ADR in place (sibling convention —
  `dependency-vulnerability-analyzer` docs/adr 0001). This file holds the
  bootstrap record — pinned toolchain, name availability, M0 measurements —
  plus the index; it holds no decisions of its own.

## Bootstrap record (2026-10-13)

- **License:** MIT declared at the bootstrap — `LICENSE` file + `license`
  field in every workspace `package.json` from the first commit (npm publish
  requires it; the JVM repo has no license).
- **Toolchain pins:** Bun 1.4.2 (ADR 0010), Biome, TypeScript strict — single
  source of truth in `package.json` + `bun.lock`.
- **Name availability (verified 2026-10-13):** the npm package `callis` is
  free (registry 404); the bare-scope endpoint is ambiguous (HTTP 405) — the
  definitive authenticated `@callis` scope check remains M0 work; no `callis`
  binary on this machine's PATH.
- **Measured facts that closed plan §7's open points** (full record in
  `docs/plan-review.md` §1.1–1.3): npm OSV `all.zip` = 218,363,616 B /
  230,324 records (index mandatory, ADR 0015); Bun 1.4.2 cross-compiles all
  7 targets + the no-AVX2 baseline from one linux-x64 host; ~81 MB binary
  floor; ~4 ms startup; workers in compiled binaries only as separate compile
  entries; config autoloading from cwd is ON by default in compiled binaries
  (hardened off, ADR 0017).

## Index

| ADR | Decision | Plan § |
| --- | --- | --- |
| [0002](0002-language-and-runtime.md) | TypeScript on Bun; core stays runtime-agnostic | §3.1 |
| [0003](0003-call-graph-engine.md) | Own call-graph engine over a per-file IR (not a wrapper) | §3.2 |
| [0004](0004-parser-selection.md) | TS compiler API parse-only; acorn fast path, differential-gated | §3.3 |
| [0005](0005-module-resolution-profiles.md) | Own resolver: runtime / source-mapping / app-code alias / bundler profiles | §3.4 |
| [0006](0006-validation-schemas.md) | Zod-validated inputs; schema failure ⇒ exit 2 | §3.5 |
| [0007](0007-cli-arg-parsing.md) | `node:util parseArgs`; JVM-compatible flag vocabulary | §3.6 |
| [0008](0008-lint-and-format.md) | Biome + `tsc --noEmit` strict (replaces Checkstyle/SpotBugs) | §3.7 |
| [0009](0009-distribution-channels.md) | Distribution channels, v1/post-v1 boundary, brand, platform support | §3.8 |
| [0010](0010-toolchain-pinning.md) | Bun 1.4.2 pinned, minimum-age rule, dual-runtime contract | §3.9 |
| [0011](0011-soundness-contract.md) | Modeled / approximated / unsupported; oracle floor as acceptance gate | §3.10 |
| [0012](0012-verdicts-and-completeness.md) | Verdict epistemics, `analysisStatus`, `completeness`, exit policy | §3.11 |
| [0013](0013-advisory-normalization.md) | Per-package records; identity + normalized-range dedup; canonical id | §3.12 |
| [0014](0014-install-reconciliation.md) | Resolution states, tie graph, fingerprint, guards, reverse reconciliation | §3.13 |
| [0015](0015-cache-keys.md) | Per-file IR / input / memo keys; one canonical definition | §3.14 |
| [0016](0016-engine-policy-separation.md) | `AnalysisResult` + separately tested policy layer | §3.15 |
| [0017](0017-threat-model.md) | Trusted vs untrusted inputs; hardening; independent verification | §3.16 |
