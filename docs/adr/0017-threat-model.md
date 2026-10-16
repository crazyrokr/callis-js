# ADR 0017 — threat model and hardening

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0009 (release verification), ADR 0006 (schema validation), ADR 0015 (integrity caveat)
- **Source:** plan §3.16, §7 (hardening + measured flags), §9 (hostile-cwd, no-native-addon)

## Decision

**Trusted inputs:**

- **The OSV source** — the pinned `osv-vulnerabilities.storage.googleapis.com`
  URL — **trusted for authenticity; the record contents it serves are still
  parsed as untrusted data** (plan v3.4 clarification).
- **User-provided SBOM / lockfile / mappings** — validated (ADR 0006),
  treated as data.
- **Signed release artifacts with a documented verification path** — v1
  actually produces them (M6: assets + SHA256SUMS + cosign + provenance,
  ADR 0009); **and signing is only as good as a documented verification
  path: the README explains how to verify cosign/provenance, the signing
  identity is independently established, and the template verifies
  independently — a digest pinned in the repo + `cosign verify` against an
  explicit certificate identity + OIDC issuer, never against a checksum
  fetched from the same release (plan v3.5, item 4)**.

**Untrusted inputs:** the application source, `node_modules`, and OSV
record contents — **parsed, never executed**. Yarn PnP artifacts join
that class: the generated `.pnp.cjs` is a layout MARKER ONLY — never
executed (node-linker layouts and their generated artifacts are data,
not code); `.yarn/install-state.gz` and `.yarn/cache/*.zip` are parsed
as data (below).

- **One subtlety pinned explicitly: a checksum computed from the same
  untrusted artifact is not independent evidence of integrity** — the pin
  `download-osv.sh` computes from the archive is trusted because the user
  trusts the source; the report records pin + snapshot refresh date so a
  poisoned snapshot is identifiable later.

**Controls for the untrusted classes:**

- **Parse-only** — no `require` of target code (risk R10: hostile-input
  fuzz corpus for the parser wrapper and JSON readers).
- **Config autoloading off at compile time** — measured 2026-10-13:
  standalone executables autoload `.env` and `bunfig.toml` from the cwd by
  default; compile with `--no-compile-autoload-dotenv
  --no-compile-autoload-bunfig`, and the **hostile-cwd test** plants both in
  the analyzed project and asserts no behavior change against the compiled
  binary.
- **Explicit resource limits (plan v3.3, P1.5):** per-file byte caps, total
  parsed-byte caps, graph node/edge caps, bounded worker concurrency,
  per-worker timeouts with a cancellation protocol; OSV-archive unpacking
  validates entry paths and rejects traversal; **yarn cache zip
  extraction validates entry paths (absolute paths and `..` segments
  rejected — zip-slip), rejects encrypted methods and zip64, and caps
  entry count and total size** (each archive is extracted fully, ONCE,
  content-addressed into the callis cache, and the recorded path is
  reused for every later need — never re-extracted); JSON readers bound nesting
  and reject oversized or malformed records; **an intentional limit hit is
  diagnosed distinctly from an OOM kill** (both map to the documented
  analysis-failure policy, exit 3).
- **No `.node` addons in the core** — a CI check fails if the bundle graph
  contains one (keeps cross-compilation plain, ADR 0004).
- Bun's reduced-memory option is verified in M0 before it enters the
  isolation contract — a container memory limit is an external constraint,
  not a guarantee of graceful failure.
