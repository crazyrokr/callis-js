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
