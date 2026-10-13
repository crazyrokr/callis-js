# ADR 0012 — verdict and completeness semantics

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0011 (soundness), ADR 0014 (component states), ADR 0016 (policy layer)
- **Source:** plan §3.11, §5.6, §6 (exit-code precedence)

## Decision

**Verdicts are evidence statements, not proofs** — the clean-result
principle (plan v3.3, the governing rule of the document): a clean result
means *no policy-triggering finding was established by the analysis*; it
must not be presented as proof that every vulnerability is unreachable
unless the analysis can substantiate that conclusion. `REACHABLE` is
positive evidence of a path; `UNREACHABLE` (label kept for JVM parity) is
*no path found within the modeled subset*, not proof of absence — a green
run with `PARTIAL` prints that, next to the verdict summary.

**The verdict set:** `REACHABLE`, `UNREACHABLE`, `NO_SOURCE` (a distinct
verdict in all three formats; a single one has no exit-code effect by
itself), `DEV_ONLY` (*excluded from reachability analysis, not safe* — the
malware gate ignores dev scope), `MALICIOUS_PACKAGE` (applies regardless of
dev scope; stable identity = canonical advisory id × package instance;
`--malware=fail|warn|ignore` changes the exit code only — the finding is
never suppressed), `NATIVE_OPAQUE` (path ends at a `.node`/WASM boundary;
`nativeBoundary: reached | unresolved`; **`REACHABLE` wins whenever the
evidence tier is met — plan v3.4 item 11; `NATIVE_OPAQUE` applies only when
the boundary crossing is the only evidence**; `--opaque-native=
fail|warn|ignore`).

**`analysisStatus` is mandatory in every report** — `COMPLETE | PARTIAL |
INCOMPLETE | NOT_PERFORMED` — refined so the status stays useful:

- **dynamic markers never demote the status** (plan v3.4 item 5 — they
  belong in `exposure`/`limitations`, because nearly every real project has
  some);
- **only *counting* unresolved imports demote** (plan v3.5 item 2 — in
  application code, or in a package that carries a candidate advisory;
  builtins are resolved per ADR 0005; library-optional / platform-specific
  imports stay in `completeness.unresolvedImports` + `limitations`);
- **unlisted loaded instances demote** (`completeness.unlistedInstalled`,
  plan v3.5 item 1, ADR 0014).

The **`completeness` block** (independent of findings, independent of
policy): per-component resolution states, `unresolvedImports` (with their
location class), `dynamicUnscoped`, `opaqueBoundaries`, `graphBuilt`,
`unlistedInstalled`, `dependencyGraph: present | absent` — each with
reasons. **`exposure`** (all false-negative exposure): `{dynamicRisk
(scoped), noSource, nativeOpaque, dynamicUnscoped, loadedNotCalled}` +
console one-liner.

**The exit code is a policy decision over findings *and* completeness**
(ADR 0016); precedence `2 > 3 > 1 > 0`; **`exitReasons[]` lists every
condition triggered, independent of the precedence winner (plan v3.5)** —
so CI that routes exit 1 and exit 3 to different queues reads the list, not
the exit code. `--require-complete` (exit 3 on `PARTIAL`) is the strict-CI
opt-in; the default stays exit 0 with the status visible.

**Schema versioning:** `schemaVersion` in every report, **independent of
`toolVersion`**; field classes (mandatory / optional / extensible)
documented; SARIF pinned to 2.1.0; unknown verdicts and properties
forward-compatible. **`limitations`**: a machine-readable array of this
run's material analysis limitations (unsupported forms actually
encountered, the import-time caveat, the `callbackInvoked` gap, native
opacity).
