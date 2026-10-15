# ADR 0011 — soundness contract

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0003 (engine), ADR 0012 (`exposure`/`limitations`), ADR 0016 (policy layer)
- **Source:** plan §3.10, §5.5, §9 (oracle, micro-corpus, metamorphic suite)

## Decision

**The engine classifies every supported construct as *modeled /
conservatively approximated / unsupported*** — the classification is part of
the release notes, not folklore:

- **modeled:** direct/flow edges, 0-CFA, library models (`packages/models`).
- **conservatively approximated:** name-based fallback under
  `--over-approximate-dynamic`; `--cha`.
- **unsupported (recorded, never dropped):** `Proxy` traps,
  dependency-injection containers, framework-generated dispatch, decorators
  beyond the modeled registrations, **re-assignment of a function or export
  after its initial definition** (the flow analysis is flow-insensitive: the
  last assignment wins, earlier aliases are lost), and **callbacks
  registered through unmodeled wrappers** (an unscoped dynamic marker
  instead).

- Unresolved behavior is **explicit in the IR and propagates**: affected
  findings carry degraded `confidence`; constructs that cannot be attributed
  to any package are counted in `exposure.dynamicUnscoped` (reported
  separately from package-scoped risk, because they cannot be scoped to
  one); every material limitation of a run is machine-readable
  (`limitations`, ADR 0012).
- **M6 dynamic-risk scope (plan §5.5):** a non-literal `require(expr)` /
  `import(expr)` in APPLICATION code is a dynamic-construct marker scoped to
  its enclosing function (or module-init at top level); such an app-scope
  marker makes EVERY `UNREACHABLE` finding of an installed package
  `dynamicRisk` — the marker could load and call that package at runtime,
  regardless of the package's own `evidence.loaded` state — and triggers the
  `DYNAMIC_RISK` notice. Package-scope markers only (no app-scope construct)
  leave the verdict untouched.
- **The 80% dynamic-edge oracle floor is an engineering acceptance gate, not
  evidence of safety** (plan v3.3, P0.1): a passing floor means the graph
  meets the ratcheted minimum; the release notes still state the supported
  subset and known limitations, and **no release claims complete
  reachability** (release criterion).
- The floor is per-app with a ±1-point tolerance and ratchets upward only
  (`floor(n+1) = max(floor(n), measurement(n))` per app); the primary metric
  is **recall on package-boundary edges** (overall recall secondary); the
  first measurement happens at M4, where the call graph exists. **Midpoint
  ramp (plan v3.5, item 3): ≥50% at M4 weeks 3–4, ≥70% at week 6, the
  ratified 80% only at exit** — a graph under construction is expected to be
  below the final floor mid-milestone; the ramp is ratified in M0 together
  with the minimum.
- Validation backing: the micro-benchmark corpus (positive *and* negative
  per framework), the dynamic-edge oracle under a tracing harness (not
  coverage — V8 coverage records statement hits, not call edges), and the
  metamorphic suite (owned M4–M5, plan v3.4).
