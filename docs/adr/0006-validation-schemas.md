# ADR 0006 — validation: schema-validated inputs, exit 2

- **Status:** accepted (2026-10-13, plan v3.6)
- **Related:** ADR 0013 (advisory normalization consumes validated records), ADR 0017 (JSON hardening)
- **Source:** plan §3.5, §5.1–5.2, §7

## Decision

**Zod (or Valibot) schemas for SBOM, OSV records, and
`vuln-mappings.json`; any schema failure maps to exit `2`** (usage/config
error — never an analysis result).

- SBOM auto-detection: CycloneDX (`bomFormat`) vs SPDX 2.x (`spdxVersion`);
  SPDX 3.x, unknown `bomFormat`, or neither marker is an explicit error,
  exit 2 (JVM ADR 0016 parity).
- A `MAL-*` record that fails schema validation is **skipped + counted,
  never downgraded** into a normal vulnerability with weaker policy (ADR
  0013).
- JSON readers bound nesting and reject oversized or malformed records
  (hardening, ADR 0017).
- `vuln-mappings.json` is validated at startup; malformed means exit 2 (JVM
  parity — the JS schema re-shapes the target fields to the JS surface but
  keeps the contract, plan §5.6).
