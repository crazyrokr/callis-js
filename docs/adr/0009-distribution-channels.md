# ADR 0009 — distribution channels, v1 boundary, brand, platform support

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0017 (independent verification), ADR 0015 (task-cache input key)
- **Source:** plan §3.8, §7 (channels), §12 item 8

## Decision

**Brand `callis`** (user decision, v3): binary `callis`, npm scope
`@callis/*`, report `tool.name` "callis", default `--output=callis-report`,
cache dir `$XDG_CACHE_HOME/callis`, workflow template `callis-check.yml`.
Project/repo **`callis-js`** — keeps its current name, no rename. The JVM
project's `reachability-analyzer` brand stays with the JVM tool; the two are
sibling projects sharing the CI contract, not one brand.

**Channels, with the v1 / post-v1 boundary explicit (plan v3.3 C1–C3,
expanded v3.4 item 3, v3.5 item 4):**

- **v1 (M6):** GitHub Release assets for all targets with `SHA256SUMS` +
  cosign signatures + provenance attestation (**new work beyond the JVM
  tool, which has no signing at all**); the multi-arch Docker image
  (`docker buildx`, `linux/amd64` + `linux/arm64`); `callis-check.yml`
  (downloads the pinned binary, verifies, and runs — a living integration
  test on the vulnerable demo with `expected-reachable.txt`); the Jenkinsfile.
- **Post-v1 (M7):** per-platform npm packages (esbuild/Biome shim pattern —
  tiny JS shim + `optionalDependencies` with `os`/`cpu`/`libc`, the no-AVX2
  `baseline` variant selected by a CPU-feature probe, install-matrix test
  M7d); the GitHub Action (M7e); **macOS notarization + Windows
  Authenticode (M7d — new work, the JVM tool ships linux-only unsigned)**;
  Turborepo/Nx task recipes (M7e/M8, consume the input key of ADR 0015).

- **Supported v1 platform (plan v3.5, item 4): Linux — glibc and musl, x64
  and arm64, plus the no-AVX2 baseline build. The macOS and Windows binaries
  ship in v1 as *experimental and unsigned*** (smoke-tested on native
  runners; a clear "experimental, unsigned" label in release notes and
  README) until M7d signs them.
- **Template verification is independent evidence (plan v3.5, item 4):**
  `callis-check.yml` pins the expected SHA256 digest *in the repo* (Renovate
  updates it with the version bump) and runs `cosign verify` against the
  documented certificate identity + OIDC issuer — **never against a
  `SHA256SUMS` fetched from the same release** (a checksum from the same
  source is not independent evidence, ADR 0017); the template installs
  cosign, and the README documents the verification path.
- **Size budget:** ~90 MB per platform accepted (plan §12 item 2; measured
  floor 81 MB, ~4 ms startup); the plain-JS distro and downloader-shim
  options stay for later releases, not v1.

## M6 implementation notes (2026-10-15)

The channels above are implemented and CI-gated:

- **One entry, 8 targets.** `scripts/build.ts` compiles `packages/cli/src/main.ts`
  to all 8 targets with `bun build --compile --minify --sourcemap
  --target=<t> --no-compile-autoload-dotenv --no-compile-autoload-bunfig
  --define BUILD_VERSION='"<version>"'`. Every artifact is validated before
  it may ship: magic bytes match the family (ELF / Mach-O / PE),
  `--version` exits 0 (host-family targets only), and `dist/SHA256SUMS`
  verifies with `sha256sum -c`. `ci.yml` runs the host target + `binary-smoke`
  + `binary-parity`; `build.yml` runs the full 8-target matrix + native smoke
  on each runner; `release.yml` signs (cosign keyless, GitHub OIDC) and
  attests (SPDX) every artifact, then publishes the GitHub Release;
  `docker.yml` pushes the multi-arch image.
- **Models are embedded, not read from disk.** The `@callis/models`
  catalogue is `--asset`-embedded; Bun serves it FLAT next to the entry
  (`/$bunfs/root/<basename>`). `loadModels()` tries the embedded candidate
  before the workspace copy, so the binary runs from ANY directory with no
  model files present (proven by `binary-smoke` check 3, an empty-cwd
  analysis). A source checkout resolves the workspace copy instead (the flat
  candidate is absent there — pinned by `callgraph.models-asset.test.ts`).
- **Hostile cwd is a tested property, not an assumption.** The binary is
  built with config autoloading off; `binary-smoke` check 4 plants a `.env`
  (redirecting `XDG_CACHE_HOME`) and a syntactically broken `bunfig.toml`
  inside the analyzed project and asserts neither changes behavior.
- **Byte-identical across runtimes.** `binary-parity` requires the compiled
  binary and the interpreted core to emit the same JSON (modulo
  `durationMillis`), JUnit (modulo `time`), and SARIF (byte-for-byte) for
  every golden demo — the release contract that a compile is behavior-neutral.
- **Golden-demo fixtures are committed data, `node_modules/` is not.** Each
  demo's installed state lives in `install/` (hand-written; the pnpm demo
  carries its `.pnpm/` layout) and its hand-pinned OSV records in `osv/`;
  `scripts/e2e.sh` materializes the gitignored `node_modules/` from `install/`
  at run time, so a fresh checkout is enough to reproduce every demo.
- **Measured (M6, Bun 1.4.2):** linux-x64 binary 85 MB with sourcemap +
  embedded models; `--version` cold start ~121 ms end-to-end.

## M7 implementation notes (2026-10-15)

The post-v1 channels ship as tested artifacts, not folklore:

- **GitHub Action (M7e):** `action/` — `action.yml` + a dependency-free
  node20 runner (`dist/index.cjs`; `.cjs` on purpose: unambiguously
  CommonJS no matter what `"type"` the consumer repo declares). The
  action downloads the release asset for the runner (OS/arch + a musl
  loader probe + an AVX2 CPU probe select the `-musl` / `-baseline`
  assets), verifies the REPO-PINNED sha256 digest (the hard gate — never
  the release's own `SHA256SUMS`, ADR 0017), optionally cosign-verifies
  when cosign is on PATH, runs callis, passes the exit code through, and
  cross-checks an optional repo-pinned `expected-reachable.txt` (a stale
  pin fails the step with exit 2, independent of the callis exit code).
  The runner is tested in `test/action.test.ts`: local-binary, digest
  mismatch, matching / stale / ABSENT pins, clean exit 0, download over
  local HTTP (a real node server — the Bun server implementation is not
  a compatible fetch target), and the full asset-selection matrix.
- **Turborepo / Nx recipes (M7e/M8):** `docs/build-tools.md` — the task
  declares the input-key components of plan §6 as inputs (application
  sources, every lockfile variant, SBOM, OSV pin, mappings, flags) and
  the report trio as outputs; until M8 the inputs are declared
  explicitly, from M8 the canonical hash is `callis --print-cache-key`
  (+ `--hash-installed` for in-place patch visibility).
