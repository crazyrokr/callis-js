# ADR 0010 — toolchain pin: Bun 1.4.2, minimum-age rule, dual-runtime contract

- **Status:** accepted (2026-10-13, plan v3.6); M0 re-verifies the then-latest stable.
- **Related:** ADR 0002 (runtime-agnostic core), ADR 0004 (parser pins), ADR 0001 (bootstrap record)
- **Source:** plan §3.9, §7 (measured facts), §8 (toolchain table)

## Decision

**Bun pinned to 1.4.2** (latest stable verified 2026-10-13, satisfying the
two-week minimum-age rule). **M0 re-verifies** against whatever stable
exists then; **every flag in plan §7 is measured on 1.4.2 and must be
re-verified after any Renovate bump** (flag churn across releases is the
standing risk, R5).

- Pin policy: exact versions only, same minimum-age rule as the JVM project
  (no release younger than two weeks); single source of truth in
  `package.json` + `bun.lock`. Renovate covers dependency, Bun, and Action
  updates (demo fixtures excluded — their vulnerable pins are deliberate,
  JVM `renovate.json5` parity).
- **Runtime-adapter contract (plan v3.3, C8):** the identical core fixture
  suite runs under **both** Bun and Node (the `platform/` adapter is the
  only difference between the two runs); the compiled-binary e2e tests
  remain a separate distribution gate.
- Measured on 1.4.2, 2026-10-13 (record in ADR 0001 / `docs/plan-review.md`
  §1.3): all 7 cross-compile targets + baseline from one host; ~81 MB;
  ~4 ms; worker separate-entry rule; config-autoload defaults.
