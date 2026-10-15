# callis

**Is this vulnerability in the SBOM actually reachable from application code?**

`callis` answers the same CI question for JavaScript and TypeScript projects
that the JVM `reachability-analyzer` answers for Java. It is a sibling project
— same CI contract, different brand — and ships as a single native binary
built with `bun build --compile` (models catalogue embedded, no runtime
dependencies, no config autoloading).

Pipeline: CycloneDX / SPDX 2.x SBOM + local OSV npm snapshot → candidate
vulnerabilities → JS/TS call graph (entry points → app source + resolved
`node_modules`) → `REACHABLE` / `UNREACHABLE` verdicts with call traces →
JSON + JUnit XML + SARIF.

> **Status:** M6 — the release pipeline exists (build, CI, release signing,
> Docker, consumer templates) and the golden demos pass in every gate.
> Post-v1 work (npm packages, GitHub Action, macOS/Windows signing) starts at
> M7. See `implementation-plan.md` v3.6 and `docs/adr/`.
>
> The clean-result principle governs every output: a clean result means *no
> policy-triggering finding was established by the analysis* — never proof
> that every vulnerability is unreachable.

## Quick start

```sh
# from source (Bun 1.4.2)
bun install
./check                              # typecheck + lint + tests + coverage gates
bun run build -- --only linux-x64    # one native binary -> dist/
dist/callis-linux-x64 --version

# run
dist/callis-linux-x64 \
  --project . --sbom bom.json --osv-dir osv-npm \
  --mappings vuln-mappings.json
```

The binary is self-sufficient: the models catalogue is embedded via
`--asset`, so it runs from any directory (even an empty one), and a project's
planted `.env` / `bunfig.toml` cannot steer it (config autoloading is
disabled at build time — `scripts/binary-smoke.ts` proves both).

## Supported platforms

| Target | Status |
| --- | --- |
| linux-x64 (glibc), linux-arm64 (glibc) | supported |
| linux-x64-musl, linux-arm64-musl, linux-x64-baseline (no AVX2) | supported |
| darwin-x64, darwin-arm64, windows-x64 | experimental, **unsigned** until M7d |

## Exit codes & reports

`0` clean, `1` any REACHABLE (or `MALICIOUS_PACKAGE` with `--malware=fail`),
`2` usage/config error, `3` analysis failure — precedence `2 > 3 > 1 > 0`.
Every report (`<base>.json`, `<base>.junit.xml`, `<base>.sarif`) carries
`analysisStatus`, `completeness`, `exposure`, `limitations` and the full
`meta.exitReasons[]` list of every triggered condition, independent of the
precedence winner. The SARIF carries `codeFlows` for every finding with a
call path: one physical source location (file + line) per hop, so
code-scanning UIs show the real call chain from the entry point to the
vulnerable function (the SBOM file stays the result anchor).

## Releasing a version

Tag `vX.Y.Z`: `release.yml` builds all 8 targets, verifies `SHA256SUMS`,
signs every artifact with cosign (keyless, GitHub OIDC) and attaches SPDX
provenance, then publishes the GitHub Release. `docker.yml` pushes the
multi-arch image to `ghcr.io/<org>/callis-js`.

## Verifying a release (consumers)

**Never** verify a binary against the release's own `SHA256SUMS` — a checksum
from the same source is not independent evidence (ADR 0017). Pin the digest
*in your repo* and verify the signature:

```sh
# 1) the repo-pinned digest (Renovate bumps it with the version)
echo "<pinned-sha256>  callis-linux-x64" | sha256sum -c -
# 2) the signature + documented certificate identity
cosign verify callis-linux-x64 \
  --certificate-identity "<owner>+callis-js@github.com" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

`templates/callis-check.yml` (GitHub Actions) and `templates/Jenkinsfile` do
exactly this, then run callis against your SBOM + snapshot and cross-check
your repo-pinned `expected-reachable.txt` — a living integration test of
your own dependency state. `templates/callis-pin.json` holds the pin.

## Docker

```sh
docker run -v $(pwd):/workspace \
  ghcr.io/<org>/callis-js:latest --sbom sbom.json --osv-dir osv
```

The image carries only the prebuilt binary (models embedded); the mounted
project is the default `--project`.

## Development gates

```sh
./check                 # tsc + biome + full test suite + coverage gates
bun run e2e             # golden demos (interpreted core or dist/ binary)
bun run build -- --only linux-x64
bun scripts/binary-smoke.ts    # self-sufficiency + hostile-cwd + bundle graph
bun scripts/binary-parity.ts   # compiled vs interpreted: byte-identical reports
```

The 23 golden demos under `examples/` cover npm/pnpm/yarn/bun, TS/JS,
CJS/ESM, every verdict family, and every exit-code path. Each demo's
installed state is committed in `install/` (hand-written fixtures; the
pnpm demo carries its `.pnpm/` layout) and its OSV records in `osv/`
(hand-pinned); `scripts/e2e.sh` materializes the gitignored `node_modules/`
from `install/` at run time, so a fresh checkout reproduces everything.

## Repository layout

```
packages/core     runtime-agnostic pipeline + AnalyzerEngine facade
packages/cli      arg parsing, exit-code mapping, compile entry
packages/models   curated data (library models, callback interfaces, ...)
tools/            coverage gate
scripts/          build, e2e, binary-smoke, binary-parity, OSV download
examples/         golden demos (npm/pnpm/yarn/bun, TS/JS, CJS/ESM)
templates/        callis-check.yml, Jenkinsfile, callis-pin.json
docs/adr/         ADRs 0001-0017
```

## License

MIT — see `LICENSE`.
