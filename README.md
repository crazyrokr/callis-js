# callis

**Is this vulnerability in the SBOM actually reachable from application code?**

`callis` answers the same CI question for JavaScript and TypeScript projects
that the JVM `reachability-analyzer` answers for Java. It is a sibling project
— same CI contract, different brand — and ships as a single native binary
built with `bun build --compile`.

Pipeline: CycloneDX / SPDX 2.x SBOM + local OSV npm snapshot → candidate
vulnerabilities → JS/TS call graph (entry points → app source + resolved
`node_modules`) → `REACHABLE` / `UNREACHABLE` verdicts with call traces →
JSON + JUnit XML + SARIF.

> **Status:** implementation in progress, milestone by milestone
> (see `implementation-plan.md` v3.6 and `docs/adr/`). The clean-result
> principle governs every output: a clean result means *no
> policy-triggering finding was established by the analysis* — never proof
> that every vulnerability is unreachable.

## Quick start

```sh
bun install
./check          # typecheck + lint + tests + coverage gates

# run (once the M5 pipeline lands; the full flag table is in
# implementation-plan section 6)
bun packages/cli/src/main.ts \
  --project . --sbom bom.json --osv-dir osv-npm \
  --mappings vuln-mappings.json
```

## The contract (flag-compatible with the JVM templates, not drop-in)

| Contract | callis behavior |
| --- | --- |
| Binary / report base / `tool.name` / cache dir / template | `callis` / `callis-report` / `callis` / `$XDG_CACHE_HOME/callis` / `callis-check.yml` |
| Exit codes | `0` clean, `1` any REACHABLE (or `MALICIOUS_PACKAGE` with `--malware=fail`), `2` usage/config error, `3` analysis failure — precedence `2 > 3 > 1 > 0` |
| Reports | `<base>.json`, `<base>.junit.xml`, `<base>.sarif`; every report carries `analysisStatus`, `completeness`, `exposure`, `limitations`, `exitReasons[]` |

Existing templates that invoke the JVM binary, glob `reachability-report.*`,
or filter on SARIF `tool.name` need a one-line rename.

## Repository layout

```
packages/core     runtime-agnostic pipeline + AnalyzerEngine facade
packages/cli      arg parsing, exit-code mapping, compile entry
packages/models   curated data (library models, callback interfaces, ...)
tools/            coverage gate
scripts/          download-osv.sh, e2e.sh
examples/         golden demos (npm/pnpm/yarn/bun, TS/JS, CJS/ESM)
docs/adr/         ADRs 0001-0017
```

## License

MIT — see `LICENSE`.
