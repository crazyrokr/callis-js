# ADR 0004 — parser: TS compiler API parse-only, acorn fast path

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0002 (runtime), ADR 0010 (pinning)
- **Source:** plan §3.3, §5.4, §9 (differential test)

## Decision

**TypeScript compiler API in parse-only mode (`ts.createSourceFile`) for
everything** — JS, TS, JSX, TSX. One library handles all four forms; it is
pure JS, so it embeds in the Bun binary on every target.

- **`acorn` is benchmarked in M0 as a fast path for plain `.js` in
  `node_modules`**, and the fast path is enabled only where a
  **differential-IR equivalence test** passes (identical IR on the supported
  syntax subset — optional chaining, class fields, decorators, JSX, error
  recovery, plan §9); otherwise the TS parser is the only path.
- **Native parsers (oxc, swc) are rejected for v1**: they rely on per-platform
  `.node` addons that complicate cross-compilation (and the no-native-addon
  CI check, plan §7). Revisit only if the M0 benchmark shows parsing
  dominates runtime.
- **Full type checking is out of v1** (it needs `lib.*.d.ts`); embedded
  trimmed `lib.d.ts` for type-checker-assisted receiver narrowing is stretch
  M7c.
