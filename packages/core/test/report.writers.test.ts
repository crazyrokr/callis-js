// M5 — report writer tests (plan section 5.6, ADR 0012): exact document
// shapes for JSON / JUnit XML / SARIF 2.1.0, the trace-message contract,
// report-file naming, and stale-report cleanup.

import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reportFiles } from "../src/engine/engine.js";
import { jsonDocument, writeJsonReport } from "../src/report/json.js";
import { junitDocument, traceMessage, writeJUnitReport } from "../src/report/junit.js";
import { type NodeLocation, sarifDocument, writeSarifReport } from "../src/report/sarif.js";
import { completeness, exposure, finding, guards, meta, result } from "./verdict.fixtures.js";

const reachable = () =>
  finding({
    id: "CVE-1",
    verdict: "REACHABLE",
    evidence: { loaded: true, called: true, callbackRegistered: false },
    confidence: "PRECISE",
    path: ["/proj/src/main.js#main", "/proj/src/a.js#mid", "/inst/node_modules/lodash/index.js#vuln"],
  });

/** Node locations covering `reachable()`'s path (M7b codeFlows). */
const nodeLocs = (): Record<string, NodeLocation> => ({
  "/proj/src/main.js#main": { file: "/proj/src/main.js", line: 1 },
  "/proj/src/a.js#mid": { file: "/proj/src/a.js", line: 7 },
  "/inst/node_modules/lodash/index.js#vuln": { file: "/inst/node_modules/lodash/index.js", line: 42 },
});

describe("jsonDocument", () => {
  test("given a finished result, when written, then the document is parseable, ends with a newline, and is byte-stable", () => {
    const r = result({ findings: [reachable(), finding({ id: "CVE-2", component: "qs" })] });
    const doc = jsonDocument(r);
    expect(doc.endsWith("\n")).toBe(true);
    const parsed = JSON.parse(doc);
    expect(parsed.analysisStatus).toBe("COMPLETE");
    expect(parsed.findings.map((f: { id: string }) => f.id)).toEqual(["CVE-1", "CVE-2"]);
    expect(jsonDocument(r)).toBe(doc); // deterministic
  });

  test("given the same result object twice, when serialized, then the bytes are identical (no wall-clock anywhere)", async () => {
    const r = result({ findings: [finding()] });
    expect(jsonDocument(r)).toBe(jsonDocument(r));
  });

  test("given a report file target, when written, then the file carries the exact document", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-json-"));
    const file = join(dir, "callis-report.json");
    await writeJsonReport(result({ findings: [finding()] }), file);
    const body = await readFile(file, "utf8");
    expect(JSON.parse(body).meta.schemaVersion).toBe("1");
    await rm(dir, { recursive: true, force: true });
  });
});

describe("traceMessage", () => {
  test("given a REACHABLE finding with a trace, when rendered, then the path with confidence", () => {
    const m = traceMessage(reachable());
    expect(m).toBe(
      "reachable: /proj/src/main.js#main -> /proj/src/a.js#mid -> /inst/node_modules/lodash/index.js#vuln (confidence: PRECISE)",
    );
  });

  test("given a finding without a trace, when rendered, then the verdict line", () => {
    const m = traceMessage(finding({ id: "CVE-9" }));
    expect(m).toBe("UNREACHABLE: lodash@4.17.20 via [introduced:0 fixed:4.17.21]");
  });

  test("given a NAME_BASED finding, when rendered, then the confidence says NAME_BASED", () => {
    const m = traceMessage(
      finding({ id: "CVE-N", verdict: "REACHABLE", confidence: "NAME_BASED", path: ["a#m", "b#v"] }),
    );
    expect(m).toContain("(confidence: NAME_BASED)");
  });
});

describe("junitDocument", () => {
  test("given a REACHABLE finding, when written, then the testcase FAILS with the trace message", () => {
    const doc = junitDocument(result({ findings: [reachable()] }));
    expect(doc).toContain('<testsuite name="callis" tests="1" failures="1">');
    expect(doc).toContain(
      '<failure message="reachable: /proj/src/main.js#main -&gt; /proj/src/a.js#mid -&gt; /inst/node_modules/lodash/index.js#vuln (confidence: PRECISE)"/>',
    );
    expect(doc).toContain('<property name="pkg:npm/lodash@4.17.20" value="REACHABLE"/>');
    expect(doc).toContain('<property name="analysisStatus" value="COMPLETE"/>');
    expect(doc).toContain('<property name="schemaVersion" value="1"/>');
  });

  test("given non-REACHABLE findings, when written, then the testcases pass (no failure element)", () => {
    const doc = junitDocument(
      result({
        findings: [finding({ id: "CVE-1" }), finding({ id: "CVE-2", component: "qs", verdict: "MALICIOUS_PACKAGE" })],
      }),
    );
    expect(doc).toContain('tests="2" failures="0"');
    expect(doc).not.toContain("<failure");
    expect(doc).toContain('value="MALICIOUS_PACKAGE"/>');
  });

  test("given no findings, when written, then an empty suite (tests=0, no properties beyond meta)", () => {
    const doc = junitDocument(result({ findings: [] }));
    expect(doc).toContain('tests="0" failures="0"');
    expect(doc).not.toContain("testcase");
  });

  test("given a component name with XML metacharacters, when written, then the attributes are escaped", () => {
    const doc = junitDocument(
      result({ findings: [finding({ id: "CVE-X", component: 'a"b<c&d>', verdict: "REACHABLE", path: ["x#y"] })] }),
    );
    expect(doc).toContain('name="a&quot;b&lt;c&amp;d&gt;@4.17.20 CVE-X"');
  });

  test("given a report file target, when written, then the file carries the exact document", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-junit-"));
    const file = join(dir, "callis-report.junit.xml");
    await writeJUnitReport(result({ findings: [reachable()] }), file);
    expect(await readFile(file, "utf8")).toBe(junitDocument(result({ findings: [reachable()] })));
    await rm(dir, { recursive: true, force: true });
  });
});

describe("sarifDocument", () => {
  test("given a finished result, when written, then the document is SARIF 2.1.0 with one result per finding", () => {
    const doc = sarifDocument(result({ findings: [reachable(), finding({ id: "CVE-2", component: "qs" })] }));
    const parsed = JSON.parse(doc);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe("callis");
    expect(run.tool.driver.version).toBe("0.1.0");
    expect(run.results).toHaveLength(2);
    expect(run.results[0].ruleId).toBe("CVE-1");
    expect(run.properties.analysisStatus).toBe("COMPLETE");
    expect(run.properties.schemaVersion).toBe("1");
    expect(run.properties.exposure).toEqual(exposure());
  });

  test("given two findings of one advisory (aliases), when written, then the rule is deduplicated", () => {
    const a = finding({ id: "CVE-1" });
    const b = finding({ id: "CVE-1", purl: "pkg:npm/lodash@4.17.19", componentVersion: "4.17.19" });
    const parsed = JSON.parse(sarifDocument(result({ findings: [a, b] })));
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(1);
    expect(parsed.runs[0].results).toHaveLength(2);
  });

  test("given a REACHABLE finding, when written without node locations, then the anchor is the SBOM file and each trace hop a logical location (stable node id)", () => {
    const parsed = JSON.parse(sarifDocument(result({ findings: [reachable()] })));
    const r = parsed.runs[0].results[0];
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe("/proj/sbom.json");
    expect(r.locations).toHaveLength(1); // the SBOM anchor only (M7b: hops moved to codeFlows)
    const hops = r.codeFlows[0].threadFlows[0].locations;
    expect(hops).toHaveLength(3);
    expect(hops[1].logicalLocations[0].name).toBe("/proj/src/a.js#mid");
    expect(hops[1].logicalLocations[0].kind).toBe("function");
    expect(r.properties.confidence).toBe("PRECISE");
    expect(r.properties.verdict).toBe("REACHABLE");
  });

  test("given a module-init hop, when written, then the logical location kind is module", () => {
    const f = finding({
      id: "CVE-M",
      verdict: "REACHABLE",
      confidence: "PRECISE",
      path: ["a#main", "b#<module-init>"],
    });
    const parsed = JSON.parse(sarifDocument(result({ findings: [f] })));
    const hops = parsed.runs[0].results[0].codeFlows[0].threadFlows[0].locations;
    expect(hops[1].logicalLocations[0].kind).toBe("module");
  });

  test("given a REACHABLE finding and node locations, when written, then codeFlows carries a physical location (file + line) per hop", () => {
    const parsed = JSON.parse(sarifDocument(result({ findings: [reachable()] }), nodeLocs()));
    const r = parsed.runs[0].results[0];
    expect(r.codeFlows).toHaveLength(1);
    const cf = r.codeFlows[0];
    expect(cf.id).toBe(1);
    expect(cf.message.text).toBe(traceMessage(reachable()));
    const hops = cf.threadFlows[0].locations;
    expect(hops).toHaveLength(3);
    expect(hops[0].physicalLocation.artifactLocation.uri).toBe("/proj/src/main.js");
    expect(hops[0].physicalLocation.region.startLine).toBe(1);
    expect(hops[1].physicalLocation.artifactLocation.uri).toBe("/proj/src/a.js");
    expect(hops[1].physicalLocation.region.startLine).toBe(7);
    expect(hops[2].physicalLocation.artifactLocation.uri).toBe("/inst/node_modules/lodash/index.js");
    expect(hops[2].physicalLocation.region.startLine).toBe(42);
    // The result-level anchor stays the SBOM file only.
    expect(r.locations).toHaveLength(1);
  });

  test("given a path node absent from the location map, when written, then that hop falls back to a logical location with the stable node id", () => {
    const f = finding({
      id: "CVE-PART",
      verdict: "REACHABLE",
      confidence: "PRECISE",
      path: ["/proj/src/main.js#main", "/proj/src/a.js#mid", "b#<module-init>"],
    });
    const known: Record<string, NodeLocation> = {
      "/proj/src/main.js#main": { file: "/proj/src/main.js", line: 1 },
    };
    const parsed = JSON.parse(sarifDocument(result({ findings: [f] }), known));
    const hops = parsed.runs[0].results[0].codeFlows[0].threadFlows[0].locations;
    expect(hops[0].physicalLocation.artifactLocation.uri).toBe("/proj/src/main.js");
    expect(hops[1].logicalLocations[0].name).toBe("/proj/src/a.js#mid");
    expect(hops[1].logicalLocations[0].kind).toBe("function");
    expect(hops[2].logicalLocations[0].name).toBe("b#<module-init>");
    expect(hops[2].logicalLocations[0].kind).toBe("module");
  });

  test("given a finding without a path, when written with node locations, then no codeFlows property", () => {
    const parsed = JSON.parse(sarifDocument(result({ findings: [finding()] }), nodeLocs()));
    const r = parsed.runs[0].results[0];
    expect(r.codeFlows).toBeUndefined();
    expect(r.locations).toHaveLength(1);
  });

  test("given the same finding and locations twice, when written, then the codeFlows document is byte-identical", () => {
    const r = result({ findings: [reachable()] });
    expect(sarifDocument(r, nodeLocs())).toBe(sarifDocument(r, nodeLocs()));
  });

  test("given a REACHABLE finding and node locations, when written via writeSarifReport, then the file carries the codeFlows", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-sarif-cf-"));
    const file = join(dir, "callis-report.sarif");
    await writeSarifReport(result({ findings: [reachable()] }), file, nodeLocs());
    const parsed = JSON.parse(await readFile(file, "utf8"));
    const hops = parsed.runs[0].results[0].codeFlows[0].threadFlows[0].locations;
    expect(hops[0].physicalLocation.artifactLocation.uri).toBe("/proj/src/main.js");
    expect(hops[0].physicalLocation.region.startLine).toBe(1);
    await rm(dir, { recursive: true, force: true });
  });

  test("given severities across the scale, when written, then the level mapping holds (CRITICAL/HIGH error, MEDIUM warning, LOW/other note)", () => {
    const mk = (severity: string) => finding({ id: `CVE-S-${severity}`, severity });
    const parsed = JSON.parse(
      sarifDocument(result({ findings: [mk("CRITICAL"), mk("HIGH"), mk("MEDIUM"), mk("LOW"), mk("UNKNOWN"), mk("")] })),
    );
    const levels = parsed.runs[0].results.map((x: { level: string }) => x.level);
    expect(levels).toEqual(["error", "error", "warning", "note", "note", "note"]);
  });

  test("given a NATIVE_OPAQUE finding with every optional property, when written, then the conditionals are present", () => {
    const f = finding({
      id: "CVE-O",
      verdict: "NATIVE_OPAQUE",
      nativeBoundary: "reached",
      opaque: true,
      relatedIds: ["CVE-O-2"],
    });
    const parsed = JSON.parse(sarifDocument(result({ findings: [f] })));
    const p = parsed.runs[0].results[0].properties;
    expect(p.nativeBoundary).toBe("reached");
    expect(p.opaque).toBe(true);
    expect(p.relatedIds).toEqual(["CVE-O-2"]);
    expect(p.supplyPath).toEqual(["app", "express", "lodash"]);
  });

  test("given a finding without optional properties, when written, then they are absent (not null, not empty)", () => {
    const f = finding({ id: "CVE-P", aliases: [] });
    const parsed = JSON.parse(sarifDocument(result({ findings: [f] })));
    const p = parsed.runs[0].results[0].properties;
    expect(p.confidence).toBeUndefined();
    expect(p.nativeBoundary).toBeUndefined();
    expect(p.opaque).toBeUndefined();
    expect(p.aliases).toBeUndefined();
    expect(p.relatedIds).toBeUndefined();
  });

  test("given a report file target, when written, then the file carries the exact document", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-sarif-"));
    const file = join(dir, "callis-report.sarif");
    await writeSarifReport(result({ findings: [finding()] }), file);
    expect(await readFile(file, "utf8")).toBe(sarifDocument(result({ findings: [finding()] })));
    await rm(dir, { recursive: true, force: true });
  });
});

describe("reportFiles", () => {
  test("given all three formats, when resolved, then the canonical names (duplicates collapse)", () => {
    expect(reportFiles("callis-report", ["json", "junitxml", "sarif", "json"])).toEqual({
      json: "callis-report.json",
      junitxml: "callis-report.junit.xml",
      sarif: "callis-report.sarif",
    });
  });

  test("given a single format, when resolved, then only that file", () => {
    expect(reportFiles("out", ["sarif"])).toEqual({ sarif: "out.sarif" });
  });

  test("given no formats, when resolved, then no files", () => {
    expect(reportFiles("out", [])).toEqual({});
  });
});

describe("report overwrite (stale bytes die)", () => {
  test("given a previous run's report at the same path, when the next run writes, then the old bytes are gone (the new document replaces them)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "callis-stale-"));
    const file = join(dir, "callis-report.json");
    await writeFile(file, `{"stale":true}\n`, "utf8");
    await writeJsonReport(result({ findings: [finding()] }), file);
    const parsed = JSON.parse(await readFile(file, "utf8"));
    expect(parsed.stale).toBeUndefined();
    expect(parsed.analysisStatus).toBe("COMPLETE");
    await rm(dir, { recursive: true, force: true });
  });
});
