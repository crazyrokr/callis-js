# ADR 0015 — cache keys: per-file IR / input / memo, one canonical definition

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0014 (install fingerprint), ADR 0017 (integrity caveat), ADR 0009 (Turborepo/Nx task hash)
- **Source:** plan §3.14, §5.4 (per-file IR key), §6 (`--print-cache-key`), §9 (invalidation matrix, M8)

## Decision

**Three key classes, one canonical definition consumed by the real cache
read/write paths** (the M8 round-trip test proves the cache consumes
exactly what `--print-cache-key` prints):

1. **Per-file IR key (tier 1):** `sha256(file contents)` + parser version +
   `IR_VERSION` + parse options, in `--cache-dir`. Because the key hashes
   *content*, an in-place patch of a loaded package changes its IR key and
   invalidates every derived result even when name, version, and install
   state are unchanged.
2. **Input key — computable *before* the run (plan v3.4, item 2); what
   `--print-cache-key` prints; the Turborepo/Nx task hash:** `sha256` over a
   sorted, canonical concatenation of (1) `toolVersion` + `IR_VERSION` +
   `schemaVersion` (a tool upgrade must never reuse a stale result); (2)
   the SBOM file sha256; (3) the OSV snapshot pin; (4) the mappings file
   sha256; (5) **every lockfile variant present** (`package-lock.json`,
   `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
   `bun.lock`/`bun.lockb`) as `path:sha256` lines; (6) the **install
   fingerprint** (ADR 0014 — the npm `node_modules/.package-lock.json`,
   pnpm `.modules.yaml`, and yarn PnP `.yarn/install-state.gz` state
   files; yarn's is hashed as RAW content, so the key covers Yarn 4.x's
   binary form), **extended by `--hash-installed` to content
   hashes of every installed file** — without it, task-level caching cannot
   see an in-place patch (documented caveat); (7) the **whole-tree
   application-source hash** (`path:sha256` lines; **the default exclusion
   list — `node_modules/`, `.git/`, `dist/`, `build/`, `.next/`,
   `coverage/`, `.turbo/`, the cache dir — is a default, plan v3.5 item 5:
   any directory that contains a resolved entry point or a loaded
   application file is auto-included with a warning** (a Nest/Next app
   whose `main` points into `dist/` analyzes those files, so edits there
   must change the key), **and `--source-exclude`/`--source-include`
   override the default**); (8) the effective policy as canonical JSON.
   `durationMillis` never enters any key.
3. **Memo key — post-run, internal (known only after the run, recorded in
   the report as `keys.memo`):** `sha256` over the entry-point set, the
   resolved dependency graph, the per-file IR keys of every loaded file,
   the library-model version, the resolver version + profile, and the
   graph-policy flags. **It is what callis's internal call-graph
   memoization consumes** — the split (v3.4 item 2) is what makes the
   pre-run key computable at all.

- **When installation integrity cannot be established** (no lockfile and no
  install-state file), **full-result caching is disabled for the run**
  (a warning is printed; per-file IR caching still applies) — risk R13.
- **M8 owns the contract:** the full invalidation matrix (source edits —
  including in auto-included directories — lockfile edits, in-place package
  patches, mapping changes, model changes, tool upgrades each change the
  relevant key tier and invalidate) and the round-trip test.
