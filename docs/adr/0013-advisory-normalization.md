# ADR 0013 — advisory normalization and dedup

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0006 (schema validation), ADR 0014 (version matching), ADR 0001 (measured record shapes)
- **Source:** plan §3.12, §5.2 (matching, dedup, canonical id), §9 (adversarial matcher tests)

## Decision

**OSV records normalize into per-package internal records** (source id,
alias union, ecosystem, package identity, affected ranges, provenance)
before any matching or dedup — because upstream data is inconsistent: one
issue can exist as several bucket files (verified: the lodash
template-injection lives in two GHSA files, the CVE id is a 404), and one
record can carry many `affected[]` entries across packages and ecosystems.

- **Merge rule (defined, plan v3.4 item 8):** records merge only when
  **ecosystem + package identity match AND the affected ranges are equal
  after normalization** — merging keeps the union of source record ids and
  aliases. **Records with differing ranges for the same package are NOT
  merged: they remain separate findings, linked by `relatedIds` and grouped
  in the report.**
- **Alias-set overlap is never the dedup rule** (partially overlapping
  alias sets can be distinct issues; slightly different sets can be the
  same one).
- **The canonical id is a presentation field, not a dedup key:** prefer the
  **lexicographically smallest `CVE-*` alias when several exist**, else the
  record's own `id`, else the lexicographically smallest alias; all aliases
  are listed in the report's `aliases` field.
- **An entry with no determinable package identity does not match** — no
  ecosystem fallback: the record's ecosystem only filters which records are
  read; it never establishes which package an advisory affects.
- **Version matching** (SEMVER ranges with pinned boundary semantics —
  `introduced` inclusive, `fixed` exclusive, `last_affected` inclusive;
  explicit `versions` lists with `-npm` suffix normalization; `ECOSYSTEM`
  treated as semver for npm; `GIT` ranges skipped with a warning only when
  no other evidence remains) runs **after component resolution**, and a
  mismatched component is evaluated against both versions with a
  `matchedOn` label (ADR 0014).
- **Pinned by tests:** golden cases (the two-GHSA-file lodash record, a
  synthetic multi-`CVE-*` record) **and adversarial cases** — partially
  overlapping alias sets (no merge), conflicting ranges across records
  (kept separate), conflicting package identities (no merge), an advisory
  lacking any package identity (matches nothing), multiple `CVE-*` aliases
  (deterministic canonical choice); matcher property-tested against the
  `semver` package.
