# ADR 0003 — own call-graph engine over a per-file IR

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0004 (parsers feed the IR), ADR 0011 (soundness contract)
- **Source:** plan §3.2, §4, §5.4–5.5, risk R2

## Decision

Build **our own demand-driven call-graph engine over a language-neutral
per-file IR, not a wrapper around an existing tool.** Parsers produce the
IR; nothing downstream sees an AST; the analysis consumes only the IR (strict
IR boundary).

- [Jelly](https://github.com/cs-au-dk/jelly) (JS/TS flow-insensitive
  call-graph + vulnerability-exposure analyzer; TypeScript, BSD-3-Clause,
  **Node-only, CLI/server with no documented library API**) is evaluated in
  the M0 spike as a benchmark oracle, run under a pinned Node outside the
  binary. It cannot be the primary engine (Node-only, no public API), but
  its permissively-licensed sources are a design reference for the library
  models (`packages/models`, embedded via `--asset`).
- **Consequence:** this is the main cost and risk (R2): M0 200-line
  call-graph prototype, strict IR boundary, and a scope cut line — v1 ships
  default mode + `--cha`; `--pointer-analysis` (Andersen-style,
  object-sensitive) is stretch M7a.

## M7a — pointer analysis (implemented 2026-10-15)

`--pointer-analysis` (opt-in; mutually exclusive with `--cha`, exit 2 when
combined) refines default RTA dispatch with inclusion-based, object-sensitive
receiver typing:

- **Type facts (per function):** `x = new C` and `x = y` copies (local
  `typeFlow`), `x = f()` where `f` returns `new C` (callee `returnTypes`),
  and `g(x)` / `g(new C)` arguments (per-parameter `paramTypes` unioned over
  every call site).
- **Dispatch:** a receiver typed `S` dispatches to `dispatchClosure(S) =
  ⋃_{C∈S} supertypeChain(C)` — the supertype closure only (itself +
  inherited chain). No down-closure: a supertype-typed receiver may hold a
  base instance, so adding subclass targets would be UNSOUND; the closure is
  sound for the verdict question (an inherited `m` is called on a `D`
  instance, so `A.m`-style edges are over-approximated, never missing).
  Supertype chains come from resolved `extends` edges; an unresolved base
  ends the chain (never invents ancestors); cycles terminate via the memo.
- **Conservative fallback (the soundness contract, ADR 0011):** a receiver
  with NO type facts keeps the default RTA behavior edge for edge — pointer
  mode never removes an edge the default build has. Refined sites are the
  only place the two builds may differ, and only by pruning default edges
  outside the receiver's closure or adding inherited ones.
- **Monotonicity gap (documented limitation):** the worklist processes a
  callee at its FIRST call site; type facts arriving at later call sites of
  the SAME function (e.g. `h(a)` then `h(b)` with `b` typed) are recorded
  but do not trigger reprocessing of the callee — the same class of
  imprecision as 0-CFA `paramFlow`. The missing edges are false negatives
  for the pointer mode only, never relative to the default build.
- **Default-build contract:** pointer state recording (`typeFlow`,
  `paramTypes`, and the eager callee processing that feeds `returnTypes`)
  runs ONLY in pointer mode; default builds are byte-identical to the
  pre-M7a engine (guarded by a byte-identity test).
- **Reporting:** `graph.stats.pointer = {sites, added, pruned}` and the
  `pointer-analysis: …` entry in `limitations[]`; `--cha` runs carry the
  existing `cha: …` limitation instead.

## Known limitations (documented, not silent)

- **Top-level nested calls (found M7c-1c):** at module top level, a call
  expression nested inside ANOTHER call's arguments
  (`console.log(pkg.vuln())`) is recorded as ONE top-level call (the outer
  one) — the inner call site is not a distinct IR entry, so no edge is
  built for it (the package reports `loaded-not-called`, i.e. a false
  NEGATIVE for reachability, never a false positive). Calls in statement or
  assignment position (`pkg.vuln();`, `const r = pkg.vuln()`) and calls
  inside function bodies are unaffected. Affects every layout equally.
