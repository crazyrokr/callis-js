# ADR 0002 — TypeScript on Bun, runtime-agnostic core

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0004 (parser), ADR 0008 (lint/coverage), ADR 0010 (pinning)
- **Source:** plan §3.1

## Decision

TypeScript in strict mode, run on Bun, **core stays runtime-agnostic.** All
`Bun.*` APIs live behind a small `platform/` adapter so the core also runs
under Node — the `platform/` adapter is the only difference between the two
runs.

- The runtime-adapter contract (plan v3.3, C8): the identical core fixture
  suite (resolver, IR, verdicts, report writers) runs under **both** Bun and
  Node; the compiled-binary e2e tests remain a separate distribution gate.
- Rationale: Node-based branch-coverage gates (Bun's coverage reports line
  and function, not branch — plan §9) and debugging without the compile step.
