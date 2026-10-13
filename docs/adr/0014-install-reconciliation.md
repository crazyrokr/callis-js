# ADR 0014 — install reconciliation: states, tie graph, fingerprint, guards, reverse direction

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0005 (resolution feeds the states), ADR 0012 (states in `completeness`), ADR 0015 (fingerprint joins the cache keys)
- **Source:** plan §3.13, §5.1 (dependencies[] graph), §5.3, §9 (guard demos)

## Decision

**Every SBOM component gets an explicit resolution state in every
report** — `RESOLVED | MISSING | VERSION_MISMATCH | AMBIGUOUS`
(`+ NOT_CHECKED` in `--sbom-only`: no filesystem in that mode);
`--strict-sources` fails on *any* non-`RESOLVED` component. A component
resolves by walking up from the project root through ancestor
`node_modules` directories (npm hoisting: a monorepo subfolder finds its
dependencies at the repo root); the per-candidate `NO_SOURCE` verdict and
the per-component status share one resolver.

- **`AMBIGUOUS` (plan v3.4 item 6, tie-graph fallback v3.5 item 7):** a
  single SBOM component cannot be tied to *any* instance through the tie
  graph, even though instances with a matching name+version exist on disk.
  **The tie graph is the SBOM `dependencies[]` when present, else the
  lockfile's resolved graph — and when neither exists, duplicate instances
  stay separate instances, never `AMBIGUOUS`** (no graph to check, no
  failure to report), with `completeness.dependencyGraph: "absent"`
  recording the gap. **Multiple instances of one name+version are the
  normal case, not ambiguity:** nested hoisting and pnpm peer-dependency
  variants are separate instances, each with its own verdict on the app's
  resolved graph — never collapsed by name+version alone, never tripping
  `--strict-sources`.
- **`VERSION_MISMATCH` (plan v3.4 item 7, order v3.5 item 8):** the name is
  present but the installed version differs. **Pipeline order is explicit:
  components are resolved *before* candidates are generated and matched**
  (the zero-candidates shortcut and the guards run after resolution). The
  advisory ranges are evaluated against **both versions — installed (what
  actually runs) and SBOM — and a finding is kept if either is in range,
  labelled `matchedOn: installed | sbom | both`**; the finding carries both
  versions. The stale-SBOM case (SBOM version outside every range,
  installed inside) still produces a finding.
- **A deterministic install fingerprint** — instance identities +
  realpaths + the install-state file content when present (npm
  `node_modules/.package-lock.json`, pnpm `.modules.yaml`; exact names
  verified in M8) — joins the cache keys (ADR 0015) and is compared against
  the lockfile's expectation, so locally patched packages, lockfile/tree
  drift, and unreadable directories are visible instead of producing
  apparently normal verdicts; loaded-file content hashes (IR keys) catch
  in-place patches of loaded packages (risk R12).
- **Reverse reconciliation (plan v3.5, item 1):** the graph's loaded
  instances are checked back against the SBOM — an instance with no
  matching SBOM component goes into `completeness.unlistedInstalled`,
  demotes `analysisStatus` to `PARTIAL`, and gets a NOTICE (an SBOM from a
  stale lockfile or a different tree cannot silently omit a package the
  application actually loads); **`--match-installed`** also generates
  candidates from the installed instances (`source: installed` on the
  finding). Under `--sbom-only` there is no load set — the check does not
  apply (risk R14).
- **Guards (fail visibly, never silently green):**
  - **Total-resolution failure:** at least one analyzable component exists
    and *every* analyzable component is non-`RESOLVED` ⇒ **exit 3** with a
    message naming the likely cause **and a minimal report in the selected
    formats listing each unresolved component** (purl + directories tried).
  - **Empty-SBOM (plan v3.4 item 12, refined v3.5 item 6):** the SBOM
    contains **zero npm components before dev filtering** ⇒ **exit 3**
    (a run that analyzes nothing is a broken input); the guard applies
    under `--sbom-only` too; the explicit opt-out `--allow-empty-sbom`
    exists for pipelines that deliberately analyze non-npm SBOMs. **An
    all-dev SBOM (npm components, every one `DEV_ONLY`) is not empty: exit
    0 with the `DEV_ONLY` verdicts listed and an explicit NOTICE** (use
    `--include-dev`).
  - Exit-code precedence `2 > 3 > 1 > 0` (ADR 0012); `MALICIOUS_PACKAGE`
    and `DEV_ONLY` components are excluded from the analyzable set the
    guards count.
