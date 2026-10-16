// Golden-demo expectations — the single source of truth for BOTH gates:
// scripts/e2e.sh (the compiled binary) and packages/core/test/e2e.demos.test.ts
// (the interpreted core, run by `bun run check`).
//
// Per demo: the expected CLI exit code, the expected findings
// (`<VERDICT> <canonical-id>`; ABSENT means "no finding for this id may
// exist"), and the console lines that must appear (each as a substring of
// one console line). Every finding in the report must be accounted for by
// an expected line (a surprise verdict fails the demo).
//
// The old per-demo expected-exit.txt / expected-reachable.txt /
// expected-notices.txt files lived here — their content was moved into this
// table (the comments carry the per-demo rationale).

export const VERDICTS = [
  "REACHABLE",
  "UNREACHABLE",
  "APPLICABLE",
  "DEV_ONLY",
  "NO_SOURCE",
  "NATIVE_OPAQUE",
  "MALICIOUS_PACKAGE",
] as const;

export type Verdict = (typeof VERDICTS)[number];

export interface ExpectedFinding {
  /** A verdict value, or ABSENT (no finding may exist for the id). */
  op: Verdict | "ABSENT";
  id: string;
}

export interface DemoExpectation {
  /** Expected process exit code. */
  exit: number;
  /** Expected findings (empty = zero findings expected). */
  findings: ExpectedFinding[];
  /** Console lines that must appear (substring of one line each; empty = none). */
  notices: string[];
}

/** One entry per examples/vulnerable-demo-* directory. */
export const goldenExpectations: Record<string, DemoExpectation> = {
  // Every npm component is dev-only: the advisory-bearing one is reported as
  // DEV_ONLY (no reachability analysis without --include-dev). Exit 0.
  "vulnerable-demo-all-dev": {
    exit: 0,
    findings: [{ op: "DEV_ONLY", id: "GHSA-dev-0008" }],
    notices: ["all components dev-only — use --include-dev to analyze them"],
  },
  // dynpkg is never statically imported; only a computed require could load
  // it.
  "vulnerable-demo-dynamic-risk": {
    exit: 0,
    findings: [{ op: "UNREACHABLE", id: "GHSA-dyn-0003" }],
    notices: [
      "exposure: 1 dynamic-risk, 0 no-source, 0 native-opaque, 0 unscoped, 0 loaded-not-called",
      "notice: 1 UNREACHABLE finding(s) of installed packages could plausibly be loaded by a dynamic construct in application code (dynamic require/import/eval)",
    ],
  },
  // Zero npm components before dev filtering: the empty-SBOM guard fires,
  // exit 3 with a minimal report.
  "vulnerable-demo-empty-sbom": { exit: 3, findings: [], notices: [] },
  // --allow-empty-sbom: the run proceeds with zero candidates, exit 0.
  "vulnerable-demo-empty-sbom-allow": { exit: 0, findings: [], notices: [] },
  // Bumped to the patched version (4.17.21, fixed is exclusive): no
  // candidate, zero findings, exit 0.
  "vulnerable-demo-fixed-pin-bun": { exit: 0, findings: [], notices: [] },
  // Import-time execution: the mapping target runs on import (module-init
  // reaches doWork) even though no exported call exists — mapping-level
  // REACHABLE below the call tier (the import-time limitation is recorded).
  "vulnerable-demo-import-time-npm-ts-esm": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "GHSA-imp-0004" }],
    notices: [],
  },
  // Present in node_modules, never imported: UNREACHABLE (installed, not
  // loaded).
  "vulnerable-demo-installed-not-required": {
    exit: 0,
    findings: [{ op: "UNREACHABLE", id: "GHSA-ghost-0001" }],
    notices: [],
  },
  // Imported for side effects, vulnerable export never called: UNREACHABLE
  // at the default call tier (evidence.loaded = true, loadedNotCalled
  // exposure).
  "vulnerable-demo-loaded-not-called": {
    exit: 0,
    findings: [{ op: "UNREACHABLE", id: "GHSA-side-0002" }],
    notices: [],
  },
  // Positive: lodash@4.17.20 prototype pollution (GHSA-424h-2jq2-7369),
  // called at module scope. Canonical id: the smallest CVE-* alias.
  "vulnerable-demo-lodash-npm-js-cjs": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // Artifact level: loaded and called (chunk). Mapping target (template)
  // never reached: method-level UNREACHABLE.
  "vulnerable-demo-mapped-negative": {
    exit: 0,
    findings: [{ op: "UNREACHABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // One advisory record covers two packages: two findings, same canonical
  // id, both REACHABLE (each package's vulnerable export is called).
  "vulnerable-demo-multipkg-npm-js-cjs": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // The package is loaded and its boundary is .node: NATIVE_OPAQUE (reached),
  // default --opaque-native=warn -> exit 0.
  "vulnerable-demo-native-boundary": {
    exit: 0,
    findings: [{ op: "NATIVE_OPAQUE", id: "GHSA-nat-0007" }],
    notices: ["exposure: 0 dynamic-risk, 0 no-source, 1 native-opaque, 0 unscoped, 0 loaded-not-called"],
  },
  // Same boundary, --opaque-native=fail -> exit 1.
  "vulnerable-demo-native-fail": {
    exit: 1,
    findings: [{ op: "NATIVE_OPAQUE", id: "GHSA-nat-0007" }],
    notices: ["exposure: 0 dynamic-risk, 0 no-source, 1 native-opaque, 0 unscoped, 0 loaded-not-called"],
  },
  // socklib's optional peer bufferutil is absent: the try/catch require is a
  // library-optional unresolved import (recorded, never counted) — no
  // advisory here, zero findings, analysisStatus stays COMPLETE. Exit 0.
  "vulnerable-demo-optional-peer": { exit: 0, findings: [], notices: [] },
  // vulnpkg is resolved but never imported (UNREACHABLE); ghost has an
  // advisory but no source on disk (NO_SOURCE). Exit 0, analysisStatus
  // PARTIAL.
  "vulnerable-demo-partial-resolution": {
    exit: 0,
    findings: [
      { op: "UNREACHABLE", id: "GHSA-vuln-0006" },
      { op: "NO_SOURCE", id: "GHSA-ghost-0001" },
    ],
    notices: [],
  },
  // pnpm virtual-store layout: same positive verdict through the .pnpm
  // store.
  "vulnerable-demo-pnpm-lodash": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // --sbom-only: the advisory applies but no call graph is built —
  // APPLICABLE, analysisStatus NOT_PERFORMED, every component NOT_CHECKED.
  // Exit 0.
  "vulnerable-demo-sbom-only": {
    exit: 0,
    findings: [{ op: "APPLICABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // --sbom-only with --strict-sources: the NOT_CHECKED components fail the
  // run.
  "vulnerable-demo-sbom-only-fail": {
    exit: 1,
    findings: [{ op: "APPLICABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
  // The SBOM (stale) omits vulnpkg, which the app loads and calls. Default:
  // no finding, the instance is listed in completeness.unlistedInstalled,
  // analysisStatus PARTIAL. Exit 0.
  "vulnerable-demo-unlisted-installed": {
    exit: 0,
    findings: [],
    notices: ["installed instance not listed in the SBOM: vulnpkg@1.0.0"],
  },
  // --match-installed: the unlisted instance produces a finding (source:
  // installed), REACHABLE, exit 1.
  "vulnerable-demo-unlisted-matched": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "GHSA-vuln-0006" }],
    notices: ["installed instance not listed in the SBOM: vulnpkg@1.0.0"],
  },
  // Stale SBOM: SBOM 2.5.0 is outside every range, installed 1.2.0 is
  // inside — the finding is kept (matchedOn: installed, VERSION_MISMATCH
  // state).
  "vulnerable-demo-version-drift": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "GHSA-drift-0005" }],
    notices: [
      "component drifted: SBOM version 2.5.0 is outside every affected range; the finding is based on the installed version 1.2.0",
    ],
  },
  // Same drift under --strict-sources: the VERSION_MISMATCH state fails the
  // run (exit 3).
  "vulnerable-demo-version-drift-strict": {
    exit: 3,
    findings: [{ op: "REACHABLE", id: "GHSA-drift-0005" }],
    notices: [
      "component drifted: SBOM version 2.5.0 is outside every affected range; the finding is based on the installed version 1.2.0",
    ],
  },
  // yarn (node-modules linker) layout, patched pin: no candidate, zero
  // findings, exit 0.
  "vulnerable-demo-yarn-fixed": { exit: 0, findings: [], notices: [] },
  // Yarn PnP layout (M7c): the lockfile tie graph + extracted zip sources
  // still yield the positive verdict for the vulnerable export.
  "vulnerable-demo-yarn-pnp": {
    exit: 1,
    findings: [{ op: "REACHABLE", id: "CVE-2020-8203" }],
    notices: [],
  },
};

interface ReportFinding {
  id: string;
  verdict: string;
}

/**
 * Compare a parsed report + console log against a demo's expectation.
 * Returns the list of mismatches (empty = the demo satisfies its
 * expectation).
 */
export function checkGoldenReport(
  demoName: string,
  report: { findings: ReportFinding[] },
  consoleLog: string,
): string[] {
  const exp = goldenExpectations[demoName];
  if (exp === undefined) return [`${demoName}: no expectation defined (add it to scripts/golden-expected.ts)`];
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const e of exp.findings) {
    const finding = report.findings.find((f) => f.id === e.id);
    if (e.op === "ABSENT") {
      if (finding !== undefined) errors.push(`${demoName}: expected no finding for ${e.id}, got ${finding.verdict}`);
    } else if (finding === undefined || finding.verdict !== e.op) {
      errors.push(`${demoName}: expected ${e.op} ${e.id}, got ${finding?.verdict ?? "no finding"}`);
    }
    if (finding !== undefined) seen.add(e.id);
  }
  for (const f of report.findings) {
    if (!exp.findings.some((e) => e.id === f.id)) {
      errors.push(
        `${demoName}: unexpected finding ${f.id} (${f.verdict}) — account for it in scripts/golden-expected.ts`,
      );
    }
  }
  // Substring match per line (the contract of the old expected-notices.txt
  // grep): the expected line must occur within one console line, so a notice
  // wrapped in `notice: … (dir)` matches its core text.
  const lines = consoleLog.split("\n");
  for (const notice of exp.notices) {
    if (!lines.some((l) => l.includes(notice))) errors.push(`${demoName}: missing notice: ${notice}`);
  }
  return errors;
}
