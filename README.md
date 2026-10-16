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
| darwin-x64, darwin-arm64, windows-x64 | experimental; signed/notarized in CI when the repo's signing secrets are configured (npm section below) |

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

## Precision modes

The default build is the sound baseline: receiver dispatch uses resolved
reachability (RTA) over text-merged receiver names. Two opt-in refinements
exist, mutually exclusive (using both is a usage error, exit 2):

- `--cha` — coarser: member calls resolve to every loaded function of the
  same name (the `cha:` limitation is reported).
- `--pointer-analysis` — finer: inclusion-based, object-sensitive receiver
  typing (Andersen-style). A receiver's type set is accumulated per
  function (`new C`, copies, call results, call-site arguments) and dispatch
  follows the supertype closure, so an inherited method is reached through a
  subclass instance and cross-function identifier merges are pruned. A
  receiver with no type facts keeps the default edges verbatim — the mode
  never removes an edge the default build has. The report carries
  `stats.pointer = {sites, added, pruned}` and a `pointer-analysis:`
  limitation with the same counts (see ADR 0003, "M7a").

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

## npm

```sh
npm install @callis/cli   # or pnpm / yarn / bun — same pattern
npx callis --project . --sbom sbom.json --osv-dir osv-npm
```

`@callis/cli` is a tiny shim (the esbuild/Biome pattern): the platform
binary comes from the `@callis/cli-<platform>` optionalDependencies
(`os`/`cpu`/`libc` fields). At run time the shim picks the right asset
from two host probes — a musl loader → the `-musl` build, an x64 host
without `AVX2` → the `-baseline` build. The macOS/Windows binaries are
signed and notarized when the repo's `APPLE_*` / `WINDOWS_PFX` secrets
are configured; until then they remain "experimental, unsigned".
On a bare alpine host the musl binary additionally needs `apk add
libstdc++` (Bun's musl build links it dynamically; the musl docker image
already carries it).

## GitHub Action

`action/` runs the pinned release binary (download + repo-pinned digest
verification + optional cosign identity), runs the analysis, fails on
REACHABLE findings or a stale `expected-reachable` pin, and exposes
`exit-code` / `report-json` outputs — see `action/README.md`.

## Turborepo / Nx

`docs/build-tools.md` ships task recipes: the task declares the
input-key components (application sources, lockfile, SBOM, OSV pin,
mappings, flags — plan §6 `--print-cache-key`) as inputs and the report
trio as outputs, so the analysis re-runs only when its content actually
changes.

## Docker

```sh
docker run -v $(pwd):/workspace \
  ghcr.io/<org>/callis-js:latest --sbom sbom.json --osv-dir osv
```

The image carries only the prebuilt binary (models embedded); the mounted
project is the default `--project`.

Per-platform images (published on version tags; the `latest`/`main-<sha>`
tags stay the multi-arch glibc default):

| Image tag | Base | Binary |
| --- | --- | --- |
| `:<ver>-linux-x64` | debian:bookworm-slim | glibc x64 |
| `:<ver>-linux-x64-baseline` | debian:bookworm-slim | glibc x64, AVX2-less CPUs |
| `:<ver>-linux-x64-musl` | alpine:3.21 | musl x64 |
| `:<ver>-linux-arm64` | debian:bookworm-slim | glibc arm64 |
| `:<ver>-linux-arm64-musl` | alpine:3.21 | musl arm64 |

darwin/windows binaries are not container-runnable (a linux container cannot
exec Mach-O/PE) — use the npm packages or the release assets there. On
alpine hosts running the musl binary directly (npm channel), `apk add
libstdc++` is required (the image already carries it).

## Development gates

```sh
./check                 # tsc + biome + full test suite + coverage gates
bun run e2e             # golden demos (interpreted core or dist/ binary)
bun run build -- --only linux-x64
bun scripts/binary-smoke.ts    # self-sufficiency + hostile-cwd + bundle graph
bun scripts/binary-parity.ts   # compiled vs interpreted: byte-identical reports
```

The 24 golden demos under `examples/` cover npm/pnpm/yarn/bun, TS/JS,
CJS/ESM, every verdict family, and every exit-code path. Each demo's
installed state is committed in `install/` (hand-written fixtures; the
pnpm demo carries its `.pnpm/` layout; the Yarn PnP demo carries its
`.yarn/` layout — cache zips + install state + the berry `yarn.lock`
from a real `yarn install`, which callis extracts into its own
content-addressed cache at run time) and its OSV records in `osv/`
(hand-pinned); `scripts/e2e.sh` materializes the gitignored
`node_modules/` from `install/` at run time, so a fresh checkout
reproduces everything. Each demo's EXPECTED result (exit code, finding
verdicts, and console notices) is a single table in
`scripts/golden-expected.ts`, consumed by BOTH gates: `scripts/e2e.sh`
(checks the compiled binary) and
`packages/core/test/e2e.demos.test.ts` (checks the interpreted core,
run by `bun run check`).

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
