# ADR 0005 — module resolution: own resolver, three profiles plus app-code aliases

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0014 (the tie graph consumes resolution), ADR 0017 (hardening)
- **Source:** plan §3.4, §5.3, §9 (M2 fixture matrix)

## Decision

**Own resolver, not `Bun.resolveSync`** — Bun's resolution has its own
conditions and quirks, and verdicts must be deterministic and
runtime-independent. Four explicit profiles:

- **(a) Runtime resolution** (authoritative for call edges): Node semantics —
  CJS + ESM, conditional `exports`/`imports` (condition ordering matters,
  nested conditions), package self-references and `#` imports,
  `main`/`index`, extension probing (`.mjs`/`.cjs`/`.mts`/`.cts`, the `type`
  field), workspaces, symlink and package-manager realpaths — **and no
  `tsconfig` `paths`/`baseUrl` at runtime: a TS alias that does not
  runtime-resolve must not invent a production call edge**.
- **(b) TS source mapping** (separate): `paths`/`baseUrl` (and project
  references) map runtime modules back to their TS source files for
  **location reporting only** — never for call edges.
- **(b2) Application-code alias resolution (plan v3.4, item 1):** the v1
  frameworks depend on `tsconfig` aliases *at runtime* (Next.js resolves
  `@/…` through its own compiler; Nest through its build). **For application
  code only**, `paths`/`baseUrl` apply when the project shows a
  runtime-resolution mechanism (a Next.js config, a Nest build config, or a
  `tsconfig-paths`/`tsc-alias`/`module-alias` dependency); such edges are
  marked `resolution: "tsconfig-alias"` with degraded `confidence`; **an
  alias with no runtime mechanism stays unresolved** (the negative fixture
  holds). M0 decides: apply b2, or drop Next/Nest from the v1 framework
  matrix.
- **(c) Bundler/framework-specific adapters:** M7c implements the
  first — **Yarn PnP as a data-driven layout profile**: the generated
  `.pnp.cjs` is a layout MARKER ONLY (never executed — ADR 0017); the
  resolution data comes from `.yarn/install-state.gz`, the berry
  `yarn.lock` graph, and the `.yarn/cache/*.zip` sources (extracted
  fully, once, content-addressed). Bare specifiers resolve strictly:
  only the importing workspace's declared dependencies resolve (per
  workspace isolation), `workspace:` refs resolve to the workspace
  directory, and anything not declared stays unresolved.

Rules:

- Every resolution decision records the conditions, candidate paths, and the
  reason for the chosen target; **an unresolved module stays unresolved** —
  counted in `completeness.unresolvedImports` (ADR 0012), never silently
  fallen back to a convenient file.
- **Core modules (`fs`, `path`, `node:fs`, …) are resolved, not
  unresolved**: the resolver classifies them as `builtin` (plan v3.5, item 2).
  Only unresolved imports in application code, or in a package that carries a
  candidate advisory, count toward `PARTIAL` (ADR 0012).
- **M2 pins the runtime profile** against the actual resolution behavior of
  the supported Node versions (fixture matrix: conditional exports including
  ordering, self-references, `#` imports, require vs ESM, `type` field,
  symlinks, nested duplicates, `npm:` aliases, and the v3.4 alias pair),
  **and runs it on a Windows runner** — case-insensitive paths, backslash
  separators, symlink behavior (plan v3.5, item 4).
