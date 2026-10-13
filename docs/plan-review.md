# Implementation-plan v1 — review and resolution record

Date: 13 October 2026. Review of `implementation-plan.md` (v1, 12 October 2026; the plan is now **v3.5** with this review's resolutions, the user's brand/license/size decisions, the v3.1 first-external-review corrections (§6), the v3.2 second-external-review corrections (§7), the v3.3 third-external-review corrections (§8), the v3.4 fourth-external-review corrections (§9), and the v3.5 fifth-external-review corrections (§10) applied) for the
JavaScript port of `/home/mk/github/dependency-vulnerability-analyzer` (the JVM tool).
Method: four parallel exploration passes over the JVM repository (CLI contract, data
layer, engine/ADRs, build/supply chain) plus live external verification (OSV bucket,
Bun 1.4.2 compile experiments on this machine). Every claim below is cited.

---

## 1. External facts verified this week (new information for the plan)

### 1.1 npm OSV snapshot — measured, not estimated

- `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` — **200 OK, 218,363,616 bytes (≈208 MiB) compressed**, `last-modified` 12 Oct 2026 (refreshed at least daily).
- Record count, read from the zip central directory without downloading the file: **230,324 records** (the standard EOCD saturates at 0xFFFF; the zip64 EOCD reports 230,324). Central directory 15.07 MB.
- Maven comparison: `Maven/all.zip` is ~10.3 MB / 7,163 records (JVM ADR 0004). So npm is **≈32× the record count, ≈21× the data**. The §5.2 "index, do not scan" decision is mandatory, and M0's "measure real record counts" question is now answered: expect 230k+ records and a 208 MB download.
- **Pin cost scales**: the pin script hashes every `*.json` (230k `sha256sum` invocations on npm vs 7k on Maven). Both the download script and the runtime `--osv-checksum` verification must parallelize (the parse pool from §5.4 can host it), or verification must be documented as a one-time-per-snapshot cost.

### 1.2 OSV record shape — three facts the plan does not state

Checked raw bucket records (e.g. `npm/GHSA-35jh-r3h4-6jhm.json`, the lodash template-injection family):

1. **One record can carry many `affected[]` entries, across ecosystems.** The lodash record lists `lodash`, `lodash-es`, `lodash.template`, `lodash-template` (all npm, different `fixed`/`last_affected` per package: `4.17.21` fixed, `4.5.0`/`1.0.0` last-affected) **and** `lodash-rails` (RubyGems, explicit versions list). Consequences:
   - A single advisory can yield **multiple candidate verdicts** in one SBOM (app installs `lodash` and `lodash-es` → two candidates from one record, each matched against its own `affected[]` entry's range). The plan's per-candidate "advisory × installed instance" model handles this, but the matching code must iterate all npm `affected[]` entries of a record and ignore non-npm ecosystems.
   - Some `affected[]` entries have **no `package` field at all** (seen in merged API views) — applicability then falls back to the record's ecosystem.
   - Explicit `versions` lists may carry ecosystem suffixes (`4.17.20-npm`) — the matcher must normalize.
2. **Records are stored in the bucket under database-specific ids, not every alias.** `npm/CVE-2021-23337.json` is a 404; the same vulnerability lives at `npm/GHSA-35jh-r3h4-6jhm.json` **and** `npm/GHSA-r5fr-rjxr-66jc.json` (two source records, each listing the full alias set). Consequences:
   - The §5.2 package index maps name → record files (fine), but **alias dedup must merge multiple files** describing the same issue — confirmed necessary, not just tidy.
   - **New decision: canonical id selection** for reporting/dedup (which alias id is printed when several exist). Proposed rule: prefer a `CVE-*` alias if present, else the record's own `id`, else the lexicographically smallest alias; the rule is pinned in the report and the golden demos. (The JVM tool doesn't need this rule — its 7,163-record Maven set is one-id-per-file in practice; npm's merged GHSA/CVE pairs make it visible.)
3. **Granularity is package-level, confirmed for npm** (ranges/versions only, no symbols) — the plan's "OSV carries no symbol data for npm" and the mapping-file design hold.

### 1.3 Bun 1.4.2 compile experiments (run on this machine, 13 Oct 2026)

The plan's §7 "points to settle in M0" are largely settled already:

| Question | Result |
| --- | --- |
| Config autoload from cwd in compiled binaries | **Real risk, real fix**: standalone executables autoload `.env` and `bunfig.toml` **by default** (`--compile-autoload-dotenv`/`--compile-autoload-bunfig` default true); `tsconfig.json`/`package.json` autoloading default false. Compile with `--no-compile-autoload-dotenv --no-compile-autoload-bunfig`. The hostile-cwd test from §7 stands. |
| Cross-compilation from one runner | **Works**: from one linux-x64 host, `--target=bun-linux-x64|bun-linux-arm64|bun-linux-x64-musl|bun-linux-arm64-musl|bun-darwin-x64|bun-darwin-arm64|bun-windows-x64` all produced valid ELF/Mach-O/PE binaries. The **`bun-linux-x64-baseline`** target (no AVX2) also exists. One build job emits all binaries, as planned. |
| Multiple entrypoints with `--compile` | **Accepted** (worker file passed alongside main). |
| Workers inside the compiled binary | **Work, with constraints.** `new Worker(new URL("./w.ts", import.meta.url))` succeeds when `w.ts` is a **separate compile entry** (embedded as `$bunfs/root/w.js`; main sees `file:///$bunfs/root/<outfile-base>`). It **fails** when the worker file is the same file as main (single entry → embedded name has no extension → `ModuleNotFound`). Data-URL workers are not supported. **Rule for M0/M3:** worker files are always separate entries; the worker URL is constructed from the main entry's `import.meta.url` with the original source filename; a compiled-binary CI job asserts the pool actually runs (the plan's §7 test, now with the exact failure mode to pin). |
| Binary size | "hello world" = **~81 MB** on every target (runtime embedded); `--bytecode` does **not** shrink it (same byte size measured). Budget answer for §12-Q2: expect ~80–90 MB per platform, ~4× the JVM tool's current 35.8 MB native image (see 1.4). Startup is a non-issue: **~4 ms** for a trivial script. |
| `--asset` | Exists (embed files/dirs preserving relative path, requires `--compile`) — the right mechanism for `packages/models` JSON, matching §7 "embedded data". |

### 1.4 JVM tool current state (from the four repo passes)

Facts that change how the JS plan reads:

- **Native image is 35.8 MB, dynamically linked (glibc+libz), single-arch linux/amd64** — the plan's "~21 MB" comparison is stale (JVM ADR 0003, amended 12 Oct 2026; 35.8 MB per ADR 0022 and `docker/Dockerfile`). Bun at ~81 MB is ~2.3×, not ~4×, the *current* JVM binary. Startup 3–13 ms (JVM) vs ~4 ms (Bun) — parity, no penalty.
- **JVM release process has no signing**: no cosign, no attestation, no SHA256SUMS, no GitHub Release assets (artifacts + GHCR only; no macOS/Windows builds at all). The JS plan §7.2 (SHA256SUMS + cosign + provenance, macOS/Windows signing) is **new work beyond the JVM tool** — keep it (it is the right thing for a security tool), but it is budget in M7d, not a carry-over.
- **JVM tool has no LICENSE file.** The JS repo must pick one before M6 publishes to npm (npm requires a license field; unlicensed = all rights reserved). **New decision item.**
- **No `action.yml` in the JVM repo** — the "GitHub template" is the `reachability-check.yml` workflow (consumer-facing, with `expected-reachable.txt` cross-check as a living integration test) plus `Jenkinsfile`. The JS plan's "GitHub Action" (M7e) is also new work; the workflow template is the carry-over.
- **Determinism is declaration-order, not sorted keys**: JSON writers emit model declaration order (byte-stable); JUnit's only varying attribute is `time`; SARIF is byte-identical; call traces = multi-source BFS, lexicographic-first shortest path (pinned, ADR 0006 amendment). The JS plan's "sorted keys" is one valid choice — but the parity claim (§9 binary parity test, byte-identical across `bun run` vs compiled) needs the same `durationMillis`-modulo treatment the JVM tool uses, or the field must be excluded from reports. **Resolved in plan v2: fixed declaration order + `durationMillis` excluded from byte-parity comparison** (see §3.12).
- **JVM has no confidence enum** (grep-verified) and **no dynamic-edge oracle**. Both exist only in the JS plan — they are deliberate upgrades, kept.
- **JVM `--entry-points` semantics**: comma-separated `class#method` **list** (not a file), **replaces** auto-detection; `--callback-interfaces` **extends** the curated list; zero detected entry points ⇒ **exit 3** (analysis failure, not usage). The JS plan §5.5 wrote `--entry-points=<file>#<export>,…` (file syntax) and §6 said "extend the curated entry-point lists" — inconsistent with the JVM contract in both shape and semantics. **Resolved in plan v2: `--entry-points=<module#export,…>` inline list that EXTENDS auto-detection, with `--entry-points-only` for the JVM-style replace (see §3.5).**
- **JVM hidden debug flags**: `--dry-run-sbom`, `--dry-run-match`, `--dry-run-graph` (parse SBOM / match candidates / build graph, each a different exit-0/2/3 contract). **The JS plan omits all three** — they are cheap, they are the standard debugging surface, and M5's e2e tests use them. Added to plan v2.
- **JVM report flattening**: `NO_CLASS_INFO` never appears in reports — it is flattened to `verdict="UNREACHABLE"` + `onClasspath=false` (console keeps the distinct NOTICE). The JS plan makes `NO_SOURCE` a distinct report verdict. Kept as a deliberate, documented deviation (more useful for JS, where a missing `node_modules` directory is a different failure than "installed but unused"); the console NOTICE contract carries over unchanged.
- **JVM exit-3 list** (port verbatim): zero-valid-records OSV dir ("refusing to pass silently"), no entry points, graph build failure/OOM, report destination not writable. The JS plan only names the OOM one; the rest added.
- **JVM `--format` default is `json,junitxml`** (SARIF is opt-in; the consumer template passes all three). The JS plan's "report trio" should keep the same default, not make SARIF default.
- **Pin-file contract (data-layer pass):** the pin file is `<DEST>.sha256` in sha256sum format (`<digest>  <DEST>`); the analyzer **never reads the pin file** — the user pipes `cut -d' ' -f1 <dest>.sha256` into `--osv-checksum`; when the flag is absent verification is skipped, but the computed pin is always recorded in report metadata (`osvSnapshotSha256`). Plan v2 carries both.
- **JVM SBOM parsers read no scope / dev-dependency data at all** (every component is analyzed regardless) — the JS plan's `DEV_ONLY`/`--include-dev` (§5.1) is a pure JS extension, now worded that way.
- **JVM `vuln-mappings.json`**: strict schema `id → [{class, method, descriptor?}]`, validated at startup (malformed ⇒ exit 2); a mapping id matching no candidate ⇒ warning; unresolved target ⇒ artifact-level fallback. The JS schema re-shapes the target fields (`export` / `file`+`function`) but the contract carries over unchanged (plan v2 §5.6 now records both).
- **JVM never parses the SBOM `dependencies[]` graph** — no supply path in its reports; the JS plan's `supplyPath` field is a deliberate extension (now noted as such).
- **Maven OSV records include `MAL-*` files** (2 of the 7,190 checked in) that flow through the generic layer with no special handling; the JS `MALICIOUS_PACKAGE` verdict + `--malware` flag is a deliberate extension (npm's MAL-* population is far larger).
- **`NO_CLASS_INFO` has no exit-code effect** (counts as unreachable; only REACHABLE triggers exit 1) — the JS `NO_SOURCE` default behavior matches; `--strict-sources` is the JS escape hatch (plan v2 §5.3/§5.6 now explicit).

---

## 2. Breakdown of the plan

Pipeline (each stage consumes only what the previous produced — the IR boundary in §5.4 is what makes the stages independently testable):

```
SBOM reader ─┐
OSV loader ──┼─> candidates (advisory × instance)
   (M1)      │
             ├─> project model: purl → install dir (M2)
             ├─> IR: parse pool + on-disk cache (M3)
             ├─> demand-driven call graph from entry points (M4, the long pole)
             ├─> verdicts: evidence tier × match level × confidence (M5)
             └─> JSON/JUnit/SARIF + exit code (M5)
```

Milestones (13–16 weeks total for M0–M6):

| M | What | Duration | Dominant risk |
| --- | --- | --- | --- |
| M0 | Spike: parser bench, OSV measure (done: 230k records), 200-line CG on demo, compile on all targets (done: works), ADRs 0001–0012 | 1–2 w | go/no-go on worker design (now settled: separate-entry rule) |
| M1 | SBOM readers, OSV loader + index, semver matcher, pin, MAL-* | 1.5 w | matcher edge cases (1.2: multi-package affected, suffixes, alias files) |
| M2 | node_modules layouts (npm/pnpm/Bun/Yarn-nm), resolver, workspaces, NO_SOURCE | 2 w | pnpm symlink realpath; purl→dir by name+version, not path |
| M3 | TS/JS/JSX/TSX → IR, CJS/ESM export tables, interop helpers, cache, parse pool | 2 w | worker-in-compiled-binary rule (1.3) |
| M4 | Demand-driven builder, flow edges, prototypes, library models, dynamic markers, entry points, `--cha`, micro-bench corpus | 3–4 w | **R1/R2: unsoundness + engine cost — the whole project hinges here** |
| M5 | Verdicts, confidence, three report writers, CLI, exit codes, facade | 2 w | parity with JVM contract (1.4) |
| M6 | Compile pipeline all targets, hostile-cwd test, parity test, templates, README | 1.5 w | Bun flag churn between releases (Renovate-gated upgrades) |
| M7–M9 | Pointer analysis, codeFlows, PnP, signing, Action, cacheability, worker isolation | post-v1 | — |

The plan's risk register (R1–R10) is sound; after this review R4 (OSV size) is converted from open risk to measured fact, and R5 (Bun compile surprises) is reduced by the §1.3 table — the remaining unknowns in R5 are only flag churn across Bun releases and the hostile-cwd test itself.

---

## 3. Ambiguities found and how they are resolved

Each item: where it was ambiguous, what the resolution is, why. Plan v2 (below) carries the resolutions.

**3.1 Evidence-tier wording (§2).** "the stricter-to-pass, noisier tier" is self-contradictory as written.
Resolution: `LOADED` = entry module imported by reachable code (weaker evidence, *more* packages pass as REACHABLE → noisier, and stricter *for the CI gate* because more things fail it). `CALLED` = a call edge crosses from outside the package into the package (API call, constructor, callback registration; stronger evidence, less noise). Default `CALLED`. Plan v2 states the direction explicitly and defines "crosses the boundary" (a call whose callee resolves into the package's IR, including `new C()` and callback *registration* where the registered function is the package's).

**3.2 `LOADED` without `CALLED` — the JS-only case.** JS executes module top-level code on import. A package can be LOADED (imported) yet never CALLED (only side effects matter) — e.g. a package whose vulnerability is in code that runs at import time.
Resolution: `LOADED`-only evidence is reported with the `CALLED=false` flag in the same finding; at the default tier such a package is UNREACHABLE but carries `installed: true` and a dynamic-risk NOTICE if its import chain includes any unresolved dynamic construct. No new exit-code semantics.

**3.3 `--entry-points` shape and semantics (§5.5 vs §6).** Plan text conflicts with itself (file syntax in §5.5, "extend" in §6) and with the JVM contract (inline list, replace semantics).
Resolution: `--entry-points=<module#export,…>` inline tokens, **extending** auto-detection; `--entry-points-only` for replace semantics (JVM parity); malformed tokens warn (not fatal), mirroring the JVM `resolveOverrides`; zero entry points after all sources ⇒ exit 3 (JVM parity, ADR 0009 territory).

**3.4 Entry-point discovery for apps with no framework and no `main`.** The plan lists `package.json` `main/module/exports/bin` plus framework patterns, but a plain `node scripts/deploy.js` app matches nothing.
Resolution: resolve `package.json` `scripts` (at least `start`, `main`-script conventions) to file entry points; if the app package yields zero entry points and `--entry-points` was not given ⇒ **exit 3 with the exact list of what was tried** (fail visibly; never silently green).

**3.5 `--callback-interfaces` shape.** Carried over verbatim from JVM (`class#method,…`); in JS the token is `module#export`. Documented in plan v2.

**3.6 `--format` default.** JVM default is `json,junitxml` (SARIF opt-in). Plan v2 keeps that; the consumer template passes all three (JVM template parity).

**3.7 Missing JVM exit-3 conditions.** Added: zero-valid-records OSV dir; no entry points; report destination not writable (§1.4).

**3.8 Missing `--dry-run-*` trio.** Added (JVM parity, M5).

**3.9 `NO_SOURCE` in reports.** Kept as a distinct verdict (deviation from JVM flattening, documented); console NOTICE contract identical in spirit to JVM's `onClasspath` NOTICE.

**3.10 `DEV_ONLY`.** Defined precisely: SBOM component present only with dev scope/property ⇒ reported as `DEV_ONLY`, **not analyzed**, never counted in the reachable total, no exit-code effect unless `--include-dev`. (JVM has no analogue — Maven SBOMs from `mvn package` rarely carry dev scope; this is JS-specific, `npm sbom` does.)

**3.11 Canonical advisory id.** New rule (§1.2.2): prefer `CVE-*` alias, else record `id`, else lexicographically smallest alias; all aliases listed in the report `aliases` field; dedup merges all files of one issue (both GHSA files in the lodash example collapse to one finding).

**3.12 Determinism and binary parity.** Fixed declaration-order keys (JVM approach, byte-stable) instead of "sorted keys"; `durationMillis` stays in JSON metadata (JVM parity) but the §9 binary-parity test compares reports **modulo `durationMillis`** (exactly the JVM native-vs-JAR rule, ADR 0003); JUnit `time` attribute likewise excluded from the parity comparison; SARIF compared byte-for-byte.

**3.13 Worker design (§5.4/§7).** Resolved by experiment (§1.3): parse workers are separate compile entries; URL built from main's `import.meta.url` + original source filename; same-file-as-main workers are forbidden by a lint/test; `bun run` (uncompiled) and the compiled binary share one code path so the pool is exercised identically in CI.

**3.14 `MAL-*` default policy (§12-Q3, half).** Default `--malware=fail` (exit 1) — a security tool whose input contains a known-malicious package should not pass CI by default; `warn`/`ignore` for triage workflows. `preinstall`/`postinstall` scripts are an informational finding (NOTICE) in all modes, never a failure by themselves. `NATIVE_OPAQUE` default: **reported, not failed** (a `.node`/WASM boundary is common and its opacity is a limitation, not a verdict) — with a per-package `opaque: true` flag so consumers can gate on it.

**3.15 Yarn PnP (§12-Q4).** **Refuse in v1** (exit 2, hint to `nodeLinker: node-modules`), as planned. PnP is a stretch item (M7c). Rationale: the plan's own resolver contract (deterministic, runtime-independent) is built on `node_modules` layouts; PnP's `.pnp.cjs` would double the resolver surface for a minority of users.

**3.16 Flag names (§12-Q5).** **Keep the JVM names exactly** where they carry over (`--sbom`, `--osv-dir`, `--osv-checksum`, `--mappings`, `--entry-points`, `--callback-interfaces`, `--cha`, `--pointer-analysis`, `--format`, `--output`, `-v`), so existing CI templates port with minimal diff. `--app-classes`/`--classpath-file` are replaced by `--project` (there is no closer JS analogue — the JVM pair split "what is app code" from "what is on the classpath", which in JS is one directory tree). `--java-version` has no JS counterpart and is dropped. New JS flags are additive only.

**3.17 Audience (§12-Q1).** **Application repositories** (Express/Nest/Next/Lambda/serverless), same as the JVM tool, which analyzes application classpaths. Libraries that publish to npm are *consumers* of this tool in their own CI, not a separate audience mode — the tool's entry-point discovery is app-shaped. M4 entry-point priority follows: server frameworks > serverless > message consumers > CLI mains.

**3.18 Binary size budget (§12-Q2).** Measured floor: **~81 MB** per platform (Bun 1.4.2, `--bytecode` makes no difference); realistic tool: **~85–95 MB** after bundling the TS compiler API and models. Cold start ~4 ms (trivial probe); a full 230k-record-indexed run is dominated by analysis, not startup. Options for the user:
  - (a) Accept ~90 MB npm package (per-platform optionalDependencies, one binary downloaded) — **recommended**;
  - (b) Same binary, but also publish a plain-JS distribution (`bun build` without `--compile`, run under Bun or Node with the platform adapter) for users who cannot accept 90 MB in devDependencies;
  - (c) Thin client: the npm package is a small downloader that fetches the platform binary from GitHub Releases on first use (network at install time — the esbuild pattern avoids this, so not recommended).
  **User decision (13 Oct, v3): (a) — accept ~90 MB per platform.** (b)/(c) stay available for a later release, not v1.

**3.19 Naming.** The repo is `callis-js` but the plan names everything `reachability-analyzer-js` / `@reachability/cli` / `reachability-check.yml`. Options:
  - (a) Keep the plan's names (continuity with the JVM tool's `reachability-analyzer` brand) — **recommended**, and rename the repo to match;
  - (b) Brand as `callis` (repo name) with `@callis/cli`;
  - (c) `@reachability/callis-js`.
  **User decision (13 Oct, v3): brand `callis`, project `callis-js`** — binary `callis`, npm scope `@callis/*` (option b, with the existing repo name kept, so no repo rename is needed). Plan v3 records these names; the plan's original `reachability-analyzer-js` name is retired.

**3.20 License.** Not in the plan at all; the JVM repo has none. **Required before M6** (npm publish, GitHub Action, Docker). Options: MIT (permissive, matches the "drop-in CI" positioning) — recommended — or Apache-2.0.
**User decision (v3): MIT.**

**3.21 `--print-cache-key` (M8).** New in the JS plan; the JVM tool has no equivalent (its cache key is Gradle-internal). Keep — it is the documented contract for Turborepo/Nx recipes — and define it as `sha256(sorted: source-glob-hashes + lockfile-hash + SBOM-hash + OSV-pin + mappings-hash + flag-set)`.

**3.22 `osv-index.json` location and invalidation.** The plan says "cached beside the snapshot and keyed by its sha256". Made precise: `osv-index.json` lives in `--cache-dir` (default `$XDG_CACHE_HOME/reachability-analyzer`, overridable; **never inside `--osv-dir`**, which may be read-only or shared); the index header stores the snapshot pin; a pin mismatch rebuilds; a missing pin (no `--osv-checksum` given) rebuilds only if the index's mtime/size fingerprint is absent.

**3.23 App-vs-library classification.** Not stated in the plan. Rule: a file is **library** if its realpath is under a `node_modules/` directory or under the pnpm store (`.pnpm/…`); everything else under the project (including workspace packages) is **application code**. Symlinks are resolved before classification; `nodeLinker: node-modules` Yarn and Bun layouts are plain `node_modules` and need no special case.

**3.24 `npm:` aliases (R7).** SBOM purls for aliased dependencies (`npm:foo@1`) name the *target* package (npm lockfiles and `npm sbom` both resolve the alias). The resolver matches by the purl's name/version against `package.json` `name`+`version` in the installed directory (never by path), which handles aliases without a dedicated code path; R7's fixture list gains an alias case.

**3.25 Bun pinning.** "pinned to the latest stable verified at M0" + minimum-age two weeks. Measured this review on **Bun 1.4.2** (13 Oct 2026). Plan v2 pins 1.4.2 as the M0 baseline with the §1.3 measurements attached, so M0 starts from evidence, not from the plan's flag guesses (which were directionally right but unverified).

**3.26 `--package-evidence` report shape.** "Reports always carry both flags" — made concrete: each finding carries `evidence: {loaded: bool, called: bool}`; the gate uses the tier selected by the flag; the report never discards the other.

---

## 4. Answers to §12 ("Decisions needed before M0 starts")

| # | Question | Answer |
| --- | --- | --- |
| 1 | Audience: apps or libraries? | **Application repositories** (§3.17). M4 priority: server frameworks → serverless → async consumers → CLI mains. |
| 2 | Binary size / cold-start budget? | Measured: **~81 MB floor, ~4 ms startup** (§3.18). **User decision: (a) — accept ~90 MB per platform (v3).** Options (b)/(c) remain available for a later release. |
| 3 | Defaults for `MAL-*` and `NATIVE_OPAQUE`? | `MALICIOUS_PACKAGE` ⇒ **fail (exit 1) by default**, `--malware=warn\|ignore` to relax. `NATIVE_OPAQUE` ⇒ **reported, not failed**, with `opaque: true` flag (§3.14). |
| 4 | Yarn PnP in v1? | **Refuse** (exit 2 + hint), stretch item later (§3.15). |
| 5 | Keep JVM flag names? | **Yes, exactly** where they carry over; `--project` replaces the two JVM classpath flags; `--java-version` dropped; JS flags additive (§3.16). |

Plus two questions the plan did not ask but the review surfaced, both now decided: **license** (MIT — user-confirmed v3, §3.20) and **brand/name** (`callis` / `callis-js` — user-confirmed v3, §3.19; the repo keeps its name, no rename).

---

## 5. What the plan got right (kept unchanged)

- Exit-code contract 0/1/2/3 + stale-report deletion at run start (JVM ADR 0009/0010 parity, verified in `AnalyzerEngine.java` L59-72).
- Pin algorithm byte-for-byte (JVM `scripts/download-osv.sh` L21-34: `LC_ALL=C` sort of `name:sha256` lines; the TS port must sort UTF-8 bytes, never `localeCompare` — and now at 230k files, parallelized).
- Demand-driven call graph, IR boundary, parse cache keyed by content sha256 + IR version.
- Evidence tiers, mapping files keyed by public export, confidence levels, dynamic-risk markers (R1 mitigation chain is the right one for an unsound JS call graph).
- The whole "fail visibly, never silently green" philosophy (NO_SOURCE loud, zero-valid-records exit 3, hostile-cwd test, binary parity, stale-report cleanup).
- Milestone ordering is right and M4 is correctly identified as the long pole (its duration was the one number v3.1 had to move: 3–4 → 6–10 weeks, v1 total now ~20–26 weeks best-case 13–16, §6).

## 6. v3.1 corrections (13 Oct 2026, external review)

Every one of the 14 points of the external review of v3 was verified accurate against the file and applied (see the v3 → v3.1 change log at the top of the plan):

- **Rebrand inconsistencies:** §1 now reads *flag-compatible, not drop-in* (including the SARIF `tool.name`-consumer note); worker pid prefix `callis:`; §12 heading → v3.1 with the stale "may still override" sentence dropped; dangling references fixed (§7 `§12-Q2 (a)` → item 2; §2 `§5.4` → `§5.5`).
- **License timing:** moved from M6 to the M0 bootstrap (every npm package needs the field from its first commit).
- **Name availability:** M0 now verifies the `@callis` scope + `callis` package name + PATH collisions. **Live pre-check (2026-10-13): the npm package `callis` is free (registry 404); the bare-scope endpoint is ambiguous (HTTP 405), so the definitive authenticated scope check stays in M0; no `callis` binary on this machine's PATH.**
- **`NO_SOURCE` can no longer go green:** if every analyzable component is `NO_SOURCE`, the run exits `3` by default (broken-environment message); `--strict-sources` extends the failure to any single `NO_SOURCE`.
- **Dev-scope malware:** `MALICIOUS_PACKAGE` applies regardless of dev scope (install scripts run on the CI machine either way).
- **Canonical id completed:** smallest `CVE-*` alias when several exist, pinned by a synthetic multi-`CVE` golden test.
- **Oracle floor hardened:** absolute minimum (proposed 80%, M0-ratified *before* the first measurement) + upward-only ratchet — a weak first result can never become the standard.
- **`--print-cache-key` defined precisely:** lockfile + application sources as `path:sha256` lines; `node_modules` content is never hashed (installed versions follow from the lockfile).
- **Exposure summary:** `dynamicRiskCount` in report metadata + the console one-liner `N UNREACHABLE with dynamic-risk markers`.
- **Budget realism:** M4 6–10 weeks; v1 total ~20–26 weeks (13–16 labelled the best case); v1 entry-point scope is fixed in M0 (R2 cut line).
- The "measured claims" point needed no change — the M0 re-verify step is already the control.

## 7. v3.2 corrections (13 Oct 2026, second external review)

All 14 points of the second review were re-checked against the v3.1 file before applying — **every claim verified accurate** (e.g. the milestone sum 1–2 + 1.5 + 2 + 2 + 6–10 + 2 + 1.5 = 16–21.5 vs. the stated ~20–26; M0's exit criterion said "oracle floor set" while §9 admitted the floor needs the M4 call graph; §5.6 still read "no exit-code effect by default"; §12 item 6 still said "before M6"; the §6 cache key hashed `bun.lockb` while §4 read `bun.lock`). All applied, in the reviewer's order:

- **Traceable timeline:** M0 re-estimated 2–3 weeks (it grew with the name check, license bootstrap, oracle harness, and scope decisions); an explicit 3–5 week integration-and-contingency buffer; v1 total **~20–28 weeks** (the 13–16 remains the best case). M0–M6 sum to 17–22.5.
- **Oracle floor at M4, not M0:** M0 ratifies the absolute minimum and builds the harness (app set, tracing method, pinned runtime); the first floor measurement happens where the call graph exists. "V8 coverage or tracing" corrected to **tracing** — coverage records statement hits, not call edges. Ratchet hardened: **per-app** floor with a ±1-point tolerance, **package-boundary recall** as the primary metric (overall recall secondary), and a documented one-release fallback if the 80% minimum is unattainable (permanent waiver ⇒ ADR).
- **NO_SOURCE guard made consistent and component-level:** resolution status per SBOM component, independent of OSV matches, evaluated before the zero-candidates exit-0 shortcut; ancestor `node_modules` traversal (npm hoisting, monorepo subfolders); **minimal report on guard failure** (purl + directories tried); new **`--sbom-only`** mode (candidate-level verdicts without `node_modules`, e.g. a MAL-only gate; guard disabled, `noCallGraph: true`); `MALICIOUS_PACKAGE` components excluded from the analyzable set; exit-code precedence **`2 > 3 > 1 > 0`** pinned in §1, §5.6, §6, and the §9 test matrix.
- **DEV_ONLY × `MAL-*`:** the precedence is now stated in §5.1 (a malicious dev dependency fails; `MAL-*` components leave the guard's set).
- **§12 item 6:** license declared at the M0 bootstrap, not "before M6".
- **`exposure {dynamicRisk, noSource, nativeOpaque}`** replaces `dynamicRiskCount`; `dynamicRisk` is **scoped** to markers that could plausibly load the package (application code, or the package's own dependents) — a global `eval` no longer flags every installed package (also the §2 NOTICE scoping).
- **`--print-cache-key` holes plugged:** all lockfile variants (`bun.lock`/`bun.lockb`, `npm-shrinkwrap.json`), `toolVersion` + `IR_VERSION` in the key, explicit source exclusion list, install-state hash when present (npm `.package-lock.json`, pnpm `.modules.yaml`; names verified in M8).
- **Minor:** SBOM dev-marker verification in M1 (CycloneDX `scope`, cdxgen properties; SPDX 2.x maps `DEV_DEPENDENCY_OF`; no markers ⇒ no `DEV_ONLY` verdicts, the safe default); per-framework v1 entry-point scope (R2 — §5.5's five groups name ~15 frameworks; M0 decides); ADR 0001 defined (bootstrap record); §7 npm line states the musl `libc` and `baseline` packages.

## 8. v3.3 corrections (13 Oct 2026, third external review)

The third review (P0.1–P0.8, P1.1–P1.8, inconsistencies C1–C8, design decisions 5.1–5.3, a 14-row boundary-test table, and a timeline assessment) was re-checked against the v3.2 file before applying — **every claim verified accurate**: e.g. §5.2 really did dedupe "by the `aliases` set" and really did fall back to the record's ecosystem when a `package` field was missing; §5.3's guard really did cover only total failure; §3.4 really did list `tsconfig` `paths` inside the runtime resolver; §5.4's IR key and §6's single `--print-cache-key` really did leave the derived-result invalidation unspecified; §5.2's `CALLED` definition really did count callback *registration*. All applied, in the reviewer's order:

- **P0.1 soundness contract** — §5.5 now classifies every construct as modeled / approximated / unsupported (Proxy, DI, re-assignment-after-definition, unmodeled wrapper callbacks listed); unresolved behavior is explicit in the IR and propagates into `confidence` + `exposure.dynamicUnscoped` + machine-readable `limitations`; the 80% oracle floor is explicitly an *acceptance gate, not evidence of safety*; release criterion "no claim of complete reachability".
- **P0.2 import-time execution** — per-module `module-init` graph node (§5.4): `import "pkg"` is an edge, top-level side effects are in the graph, a mapping target executed at import time is REACHABLE at mapping level even when the artifact is below the `call` tier; `evidence.callbackRegistered` is its own field (registration ≠ invocation; `callbackInvoked` deferred and documented).
- **P0.3 advisory normalization** — per-package internal records; dedup only on verified identity + compatible ranges (union of ranges/source ids); alias-set overlap is never a dedup rule; canonical id is presentation-only; **entries without a package identity do not match** (ecosystem fallback removed); adversarial tests (overlapping aliases, conflicting ranges, conflicting identities, no identity).
- **P0.4 install reconciliation** — states `RESOLVED | MISSING | VERSION_MISMATCH | AMBIGUOUS` in every report; `--strict-sources` now fails on any non-`RESOLVED` (folded in rather than a new flag); deterministic **install fingerprint** joins the cache keys; loaded-file content hashes catch in-place patches; new risk R12.
- **P0.5 resolution profiles** — three explicit profiles: runtime (authoritative, **no `tsconfig` paths at runtime** — the v3.2 contradiction), TS source mapping (locations only), bundler adapters (post-v1); per-decision recording; unresolved stays unresolved; M2 fixtures pinned against actual supported-Node behavior, including the no-runtime-target alias negative case.
- **P0.6 native opacity** — boundaries are graph nodes (package, symbol, call sites) with `nativeBoundary: reached | unresolved`; new `--opaque-native=fail|warn|ignore` (default `warn`); *engine opacity ≠ component unreachability*.
- **P0.7 cache tiers** — three keys (per-file IR / call-graph / final-report, what `--print-cache-key` prints), install fingerprint, full-result caching disabled when installation integrity cannot be established, cache read/write consuming the same canonical definition (M8 round-trip + invalidation matrix); new risk R13.
- **P0.8 completeness state** — mandatory `analysisStatus: COMPLETE | PARTIAL | INCOMPLETE | NOT_PERFORMED` + `completeness` block in every report; the exit code is a policy decision over findings *and* completeness; the 99/100 partial-resolution case is now a golden demo (exit 0, `PARTIAL`, visible).
- **P1.1 verdict epistemics** — `UNREACHABLE` (label kept for JVM parity — a rename would break the compatibility story) documented as *no path found within the modeled subset*, not proof of absence; the reviewer's **clean-result principle is now §2's governing rule**.
- **P1.2–P1.6 applied** — DEV_ONLY "excluded, not safe" + build-tool fixtures; `--sbom-only` contract (`NOT_PERFORMED`, no reachability verdicts, formats must not misrepresent); parser fast path gated on differential-IR equivalence; worker hardening limits (byte/node/edge caps, timeouts + cancellation, archive traversal validation, JSON nesting bounds, limit-hit vs OOM diagnostics, Bun reduced-memory semantics verified in M0); stable identity for malware findings (`warn|ignore` never suppresses; malformed `MAL-*` never downgraded).
- **P1.7 determinism normalization contract** — path separators, Unicode NFC, stable ordering of nodes/edges/aliases/diagnostics, trace tie-breaks, SARIF rule ids + URIs, JUnit names, logical-location duplicates; traversal-order repeatability test.
- **P1.8 npm platform selection** — supported-platform matrix, shim diagnostics (no generic spawn errors), CPU-feature probe for the baseline variant (os/cpu/libc fields do not express AVX2), install-matrix test (npm/pnpm/yarn node-modules/bun × clean/cached/skipped-optional/baseline hardware).
- **C1–C8** — v1 distribution frozen: **standalone binary + `callis-check.yml` + Jenkinsfile**; npm packages, the GitHub Action, and the build-tool cache integration are post-v1 (M7); compatibility matrix added to §1; the framework matrix freezes in M0 with per-framework positive + negative fixtures; runtime-adapter contract (identical core fixtures under Bun and Node).
- **5.1–5.3** — threat model (trusted vs untrusted inputs; *a checksum computed from the same untrusted artifact is not independent evidence*; signing needs a documented verification path); engine/policy separation (`AnalysisResult` + separately tested policy layer, ADR 0016); `schemaVersion` independent of `toolVersion`, SARIF pinned to 2.1.0.
- **Tests** — the review's 14 boundary tests folded into the §9 golden demos, unit/matcher cases, exit-code matrix, and a new **metamorphic suite** (behavior-preserving transforms must not remove known paths).
- **Timeline** — 20–28 weeks retained with the upper end as a baseline; **M4 midpoint scope-reduction trigger** added (shrink the framework set or defer precision features rather than compress validation).

Adjustments made instead of the literal proposal (recorded here so the next review sees the reasoning): (1) `UNREACHABLE` is **not** renamed to `NO_PATH_FOUND` — the label carries the JVM-parity contract; the epistemics is documented and `analysisStatus` carries the qualification; (2) `callbackInvoked` evidence is deferred to post-v1 (it requires invocation tracking) and is listed in `limitations` instead; (3) strict installation consistency is folded into `--strict-sources` semantics rather than a new flag; (4) the native states are a `nativeBoundary` field on `NATIVE_OPAQUE` rather than two new verdicts (report stability for consumers).

## 9. v3.4 corrections (13 Oct 2026, fourth external review)

The fourth review (three "blocking" design items, eight "contradictions", three "gaps" — 14 items, with the reviewer recommending items 1–3 first because they change v1 scope) was re-checked against the v3.3 file before applying — **every claim verified accurate**: e.g. §6's tier-2 key really did hash the loaded files' IR keys (known only post-run, so `--print-cache-key` really could not be computed before the run); the release signing/attestation was really in M7d while the v1 template needed a binary it could actually download; the M0–M6 sum really was 17–22 (the "17–22.5" was an arithmetic slip) and v3.3's additions to M0/M2/M5/M6/M8 were really unpriced; §5.6 really did fold the dynamic markers into `PARTIAL` (it would fire on every real run); §5.3's `AMBIGUOUS` really contradicted §3.4's "pnpm peer variants are separate instances"; the merge rule's "compatible ranges" really was undefined; §6's `--sbom-only` row really did say `NO_SOURCE` while its own guard was disabled; §5.2's `CALLED` really did count callback registration; and M5 really did cite a §9 boundary-test table that did not exist. All 14 applied, in the reviewer's order:

- **Item 1 (blocking) — `tsconfig` aliases** — the v3.3 "no `paths` at runtime" rule did break the v1 frameworks that depend on them. §3.4 gains (b2): **application-code-only** alias resolution, applied only when the project shows a runtime mechanism (Next config, Nest build, `tsconfig-paths`/`tsc-alias`/`module-alias`); such edges carry `resolution: "tsconfig-alias"` with degraded confidence; no mechanism ⇒ no edge (the v3.3 negative fixture holds). M0 decides — apply, or drop Next/Nest from the v1 matrix; M2's fixture pair pins both directions.
- **Item 2 (blocking) — pre-run cache key** — `--print-cache-key` now prints the **input key**, computable before the run (versions, SBOM, OSV pin, mappings, every lockfile variant, install fingerprint, whole-tree application-source hash, flags — the Turborepo/Nx task hash); the **memo key** (entry points, resolved graph, loaded-file IR keys, model/resolver versions) is internal, recorded as `keys.memo`, and is what internal memoization consumes; new `--hash-installed` (content-hashes installed files into the input key; without it, task-level caching cannot see an in-place patch — documented); full-result caching disabled when installation integrity cannot be established.
- **Item 3 (blocking) — verifiable, downloadable v1 binary** — M6 (re-estimated 2.5 weeks) owns the **GitHub Release assets for all targets + `SHA256SUMS` + cosign signatures + provenance attestation + the multi-arch Docker image via `docker buildx`** (now explicit v1, not an M7d item); the v1 completion line is updated accordingly; the template downloads the pinned binary from the M6 release and verifies SHA256 + cosign before running; M7d keeps per-platform npm packages + macOS notarization + Windows Authenticode only.
- **Item 4 — timeline arithmetic** — per-milestone re-estimate: M0 3–4, M2 2.5, M5 3, M6 2.5, M8 1.5 → M0–M6 sum to **20.5–25.5 weeks** (v3.3's added work finally priced); +3–5 buffer → **v1 ~24–31 weeks** (best case 20.5; the original 13–16 estimate is historical — pre-measurement, pre-scope-freeze). The M4 scope-reduction trigger now carries a **measurable criterion** (weeks 3–4: package-boundary recall below the ratified minimum on 2 of the 3 initial apps, or the micro-corpus passes below 95% → shrink the framework set or defer precision features).
- **Item 5 — `PARTIAL` fired everywhere** — `PARTIAL` now means only non-`RESOLVED` components or unresolved imports (dynamic markers no longer demote the status; they feed `exposure`); new `--require-complete` for strict CI (any non-`COMPLETE` ⇒ exit 3).
- **Item 6 — `AMBIGUOUS`** — now only when an SBOM component cannot be tied to an installed instance through the SBOM `dependencies[]` graph; multiple instances of one name+version (pnpm peer variants, hoisting) are the normal case — separate instances, separate verdicts, never tripping `--strict-sources`. M2's exit check pins the peer-variant case.
- **Item 7 — `VERSION_MISMATCH`** — advisory ranges are matched against the **installed** version, not the SBOM-declared one; the finding carries both (`componentVersion` + `installedVersion`).
- **Item 8 — merge rule defined** — "compatible ranges" = **equal after normalization** → merge (union of source ids/aliases); records with differing ranges stay **separate findings, linked by `relatedIds`** and grouped in the report (stable identity per finding preserved).
- **Item 9 — `--sbom-only`** — every component `resolutionState: NOT_CHECKED` (no filesystem in this mode — `NO_SOURCE` is dropped, not misused); new `--fail-on-applicable` (any applicable non-malicious advisory ⇒ exit 1); **without it, only `MAL-*` affects the exit code** — reported, never silently green, and the report states exactly what was checked.
- **Item 10 — `called` vs `callbackRegistered`** — `called` = direct call or `new` only; `callbackRegistered` = a package function passed as a value (registration ≠ invocation); the `call` tier is met by either by default, `--call-evidence=direct` requires direct calls.
- **Item 11 — `REACHABLE` vs `NATIVE_OPAQUE`** — `REACHABLE` wins whenever the evidence tier is met; `NATIVE_OPAQUE` applies only when the path ends at a boundary **and the tier is not otherwise met** (the overlap is resolved by the tier, not by precedence between verdicts).
- **Item 12 — empty SBOM** — zero analyzable npm components ⇒ **exit 3** (a run that analyzes nothing is a broken input, never a clean one); explicit opt-out `--allow-empty-sbom`; new §9 demo + exit-matrix row; §1's exit-3 list gained the guard.
- **Item 13 — import-time exposure** — `exposure.loadedNotCalled`: packages LOADED but below the configured evidence tier — the import-time exposure that unmapped advisories cannot see, visible in the console one-liner without opening findings.
- **Item 14 — dangling references / stale text** — §9 gained the **15-row boundary-test table** M5 cited; the §12 heading is v3.4 with the v3.4 change log referenced; ADR references are disambiguated (`JVM ADR 00xx` vs `callis ADR 00xx`); the threat-model wording now reads "the OSV source is trusted for authenticity, its contents are untrusted" and notes v1 produces signed artifacts (M6); the metamorphic suite's milestone ownership is M4–M5.

No material deviations — all 14 applied as proposed. The only v1 scope changes are the ones item 3 forces (verifiable, downloadable, signed binary and Docker image, both now M6 exit criteria) and the re-estimate of item 4; items 1 and 2 change how existing v1 features work, not what v1 ships.

## 10. v3.5 corrections (13 Oct 2026, fifth external review)

The fifth review (three "High" items that could hide real findings or break the new semantics, five "Medium" definition fixes, plus a housekeeping list — 9 points) was re-checked against the v3.4 file before applying — **every claim verified accurate**: e.g. §5.2 really did read "only records for packages in the SBOM" and §5.3 really reconciled SBOM→disk only, so an unlisted-installed package really escaped with exit 0 `COMPLETE`; §5.6's `PARTIAL` really still counted *every* recorded unresolved import (and §3.4 had no builtin rule — `node:fs` would be "unresolved" in every project); the M4 trigger really compared weeks 3–4 recall against the 80% *final* target mid-milestone; the template really verified against the release's own `SHA256SUMS` (same source — §3.16's "not independent evidence" rule); the exclusion list really excluded `dist/` while §5.5 entry points could point into it; "zero *analyzable* npm components" really included all-dev SBOMs; the v3.4 `AMBIGUOUS` rule really required the SBOM `dependencies[]` graph (SPDX 2.x often has none); the "fixed pin → zero candidates" demo really proved candidates are version-filtered at generation, so the stale-SBOM reverse case produced no candidate at all; and every housekeeping item was real (the §2 "budgeted in M7d", R13 "IR / call-graph / report", R1's 3-field exposure, R12 without `NOT_CHECKED`, §3.8's unmarked "GitHub Action", and the §9 bold chain — the v3.4 alias-pair edit really left an odd number of `**` in the resolver bullet, swallowing the rest of the bold). All nine applied:

- **Item 1 (high) — installed-but-unlisted packages** — the reverse direction now exists: the graph's loaded instances are checked back against the SBOM; an unlisted instance → `completeness.unlistedInstalled` + `PARTIAL` + NOTICE; new **`--match-installed`** generates candidates from the installed instances (`source: installed` on the finding); golden demo (SBOM omits a vulnerable transitive the app loads); new risk R14.
- **Item 2 (high) — `PARTIAL` noise from unresolved imports** — builtins are resolved (`builtin` classification, never unresolved); only unresolved imports **in application code, or in a package that carries a candidate advisory**, count toward `PARTIAL`; everything else stays in `completeness.unresolvedImports` + `limitations`; the `ws`-without-`bufferutil` demo stays `COMPLETE`.
- **Item 3 (high) — the M4 trigger compared mid-milestone progress to the final target** — now a **ramp**: ≥50% of observed-edge recall at weeks 3–4, ≥70% at week 6, the ratified 80% only at exit; the micro-corpus ≥95% threshold stays (a fair early gate); the ramp is ratified in M0 together with the minimum.
- **Item 4 (high) — non-independent verification + unclear platform support** — the template now **pins the expected digest in the repo (Renovate updates it with the version bump) and runs `cosign verify` against the documented certificate identity + OIDC issuer** (cosign installed by the template; never the release's own `SHA256SUMS`); **Linux (glibc/musl, x64/arm64 + baseline) is the supported v1 platform — macOS/Windows ship as experimental and unsigned** (smoke-tested; M7d signs them); M2's fixture matrix also runs on a Windows runner (case-insensitive paths, backslashes, symlink behavior).
- **Item 5 (medium) — the exclusion list could hide analyzed files** — the list is now the default: any directory containing a resolved entry point or a loaded application file is auto-included with a warning; `--source-exclude`/`--source-include` override; the `dist/`-entry-point fixture and an invalidation-matrix row pin it.
- **Item 6 (medium) — the empty-SBOM guard fired on all-dev SBOMs** — "empty" = zero npm components **before dev filtering**; an all-dev SBOM exits 0 with the `DEV_ONLY` verdicts listed and an explicit NOTICE; the guard applies under `--sbom-only` too (stated); `--fail-on-applicable` without `--sbom-only` is a usage error (exit 2).
- **Item 7 (medium) — `AMBIGUOUS` needed an SBOM dependency graph** — the tie graph now falls back: SBOM `dependencies[]` → lockfile's resolved graph → separate instances (never `AMBIGUOUS`, never tripping `--strict-sources`) with `completeness.dependencyGraph: "absent"`.
- **Item 8 (medium) — circular pipeline order** — the order is stated explicitly: **resolve components first, then generate and match candidates**; a mismatched component is evaluated against both versions, and a finding is kept if either is in range, labelled `matchedOn: installed | sbom | both` (new report field, alongside `source`; `--dry-run-match` updated to the same order).
- **Housekeeping** — §2 Distribution row (release assets + cosign + provenance budgeted M6; macOS/Windows signatures M7d); R13 → "per-file IR / input / memo"; R1 → the five `exposure` fields; R12 gains `NOT_CHECKED`; §3.8 marks v1 vs post-v1; the §9 markdown breakage fixed (the resolver bullet's bold closed properly; the boundary-test table moved out of the bullet list — now a standalone paragraph — with six v3.5 rows added); the timeline states the exact sum (**23.5–30.5 weeks, ~24–31**); the report carries **`exitReasons[]`** — every triggered condition, independent of the precedence winner — so CI routing exit 1 vs exit 3 reads the list, not the exit code (README documents it; the exit matrix tests co-occurrence).

No material deviations — all nine applied as proposed. ADR numbers are unchanged: v3.5 refines existing ADRs (0005 resolver, 0011 soundness contract, 0012 verdict/completeness, 0013 normalization, 0014 install reconciliation, 0015 cache keys, 0016 threat model); the new mechanics (reverse reconciliation + `--match-installed`, the ramp, the platform-support declaration, `exitReasons[]`) are recorded inside them, not as new ADRs.
