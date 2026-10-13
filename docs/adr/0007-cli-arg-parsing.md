# ADR 0007 — CLI: `parseArgs`, JVM-compatible flag vocabulary

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0012 (exit codes over the flag set), ADR 0009 (template)
- **Source:** plan §3.6, §1 (compatibility matrix), §6

## Decision

**`node:util parseArgs` plus a thin wrapper** (zero dependencies, works in
Bun); unless M0 shows subcommand ergonomics are needed, then `commander`.

- **Flag vocabulary kept exactly from the JVM CLI** (verified flag-for-flag),
  so existing CI templates port with minimal diff: `--app-classes` +
  `--classpath-file` collapse into `--project`; `--java-version` has no JS
  counterpart and is dropped.
- **JS-only flags are additive** (`--sbom-only`, `--strict-sources`,
  `--include-dev`, `--include-tests`, `--malware`, `--package-evidence`,
  `--call-evidence`, `--over-approximate-dynamic`, `--opaque-native`,
  `--print-cache-key`, `--hash-installed`, `--require-complete`,
  `--fail-on-applicable`, `--allow-empty-sbom`, `--match-installed`,
  `--source-exclude`, `--source-include`) — every deliberate deviation is
  labeled in the compatibility matrix (plan §1), not discovered downstream.
- Exit-code precedence `2 > 3 > 1 > 0` (ADR 0012); every triggered condition
  is also listed in the report's `exitReasons[]` (plan v3.5).
