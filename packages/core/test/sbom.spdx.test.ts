import { describe, expect, test } from "bun:test";
import { parseSpdx } from "../src/sbom/spdx.js";
import { UsageError } from "../src/util/errors.js";

function spdx(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    spdxVersion: "SPDX-2.3",
    name: "doc",
    packages: [
      { spdxId: "SPDXRef-Package-lodash", name: "lodash", versionInfo: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
      { spdxId: "SPDXRef-Package-jest", name: "jest", versionInfo: "29.0.0", purl: "pkg:npm/jest@29.0.0" },
    ],
    relationships: [
      {
        spdxElementId: "SPDXRef-Package-jest",
        relatedSpdxElement: "SPDXRef-Document",
        relationshipType: "DEV_DEPENDENCY_OF",
      },
    ],
    ...overrides,
  });
}

describe("SPDX 2.x reader (plan 5.1)", () => {
  test("given an SPDX-2.3 document with a DEV_DEPENDENCY_OF relationship, when parsed, then the marked package is dev-only", () => {
    const r = parseSpdx(spdx(), "bom.json", "sha");
    expect(r.format).toBe("spdx-2.3");
    expect(r.components.map((c) => c.name)).toEqual(["lodash", "jest"]);
    expect(r.components[0]?.devOnly).toBe(false);
    expect(r.components[1]?.devOnly).toBe(true);
    expect(r.hasDevMarkers).toBe(true);
  });

  test("given an SPDX document without DEV_DEPENDENCY_OF relationships, when parsed, then no component is dev-only (safe default)", () => {
    const r = parseSpdx(spdx({ relationships: [] }), "bom.json", "sha");
    expect(r.hasDevMarkers).toBe(false);
    expect(r.components.every((c) => !c.devOnly)).toBe(true);
  });

  test("given a DEPENDS_ON relationship, when parsed, then it is carried as a dependency edge", () => {
    const r = parseSpdx(
      spdx({
        relationships: [
          {
            spdxElementId: "SPDXRef-Package-lodash",
            relatedSpdxElement: "SPDXRef-Document",
            relationshipType: "DEPENDS_ON",
          },
        ],
      }),
      "bom.json",
      "sha",
    );
    expect(r.dependencies).toEqual([{ ref: "SPDXRef-Package-lodash", dependsOn: ["SPDXRef-Document"] }]);
  });

  test("given a non-npm package purl, when parsed, then it is skipped with a warning", () => {
    const r = parseSpdx(
      spdx({
        packages: [
          { spdxId: "P1", name: "httpclient", purl: "pkg:maven/org.apache/httpclient@4.5.13" },
          { spdxId: "P2", name: "lodash", purl: "pkg:npm/lodash@4.17.20" },
        ],
        relationships: [],
      }),
      "bom.json",
      "sha",
    );
    expect(r.components.map((c) => c.name)).toEqual(["lodash"]);
    expect(r.warnings[0]).toContain("pkg:maven/org.apache/httpclient@4.5.13");
  });

  test("given an SPDX 3.x document, when parsed, then it is refused with a UsageError (exit 2)", () => {
    expect(() => parseSpdx(spdx({ spdxVersion: "SPDX-3.0" }), "bom.json", "sha")).toThrow(UsageError);
  });

  test("given a non-JSON document, when parsed, then a UsageError is thrown (exit 2)", () => {
    expect(() => parseSpdx("nope", "bom.json", "sha")).toThrow(UsageError);
  });
});
