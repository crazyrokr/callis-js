import { describe, expect, test } from "bun:test";
import { parseCycloneDx } from "../src/sbom/cyclonedx.js";
import { UsageError } from "../src/util/errors.js";

function cdx(specVersion: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion,
    version: 1,
    components: [
      { name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", type: "library" },
      {
        name: "@types/lodash",
        version: "4.14.195",
        purl: "pkg:npm/%40types/lodash@4.14.195",
        type: "library",
        scope: "excluded",
      },
      { name: "httpclient", version: "4.5.13", purl: "pkg:maven/org.apache/httpclient@4.5.13", type: "library" },
      { name: "no-purl", version: "1.0.0", type: "library" },
    ],
    dependencies: [
      { ref: "pkg:npm/lodash@4.17.20", dependsOn: [] },
      { ref: "app", dependsOn: ["pkg:npm/lodash@4.17.20"] },
    ],
    ...extra,
  });
}

describe("CycloneDX 1.4-1.6 reader (plan 5.1)", () => {
  test("given a 1.5 SBOM, when parsed, then npm components are extracted with dev markers", () => {
    const r = parseCycloneDx(cdx("1.5"), "bom.json", "sha");
    expect(r.format).toBe("cyclonedx-1.5");
    expect(r.components.map((c) => c.name)).toEqual(["lodash", "@types/lodash"]);
    expect(r.components[0]?.version).toBe("4.17.20");
    expect(r.components[0]?.devOnly).toBe(false);
    expect(r.components[1]?.devOnly).toBe(true);
    expect(r.hasDevMarkers).toBe(true);
    expect(r.warnings).toEqual([
      "non-npm component skipped: pkg:maven/org.apache/httpclient@4.5.13",
      "component without purl skipped: no-purl@1.0.0",
    ]);
  });

  test("given a 1.4 or 1.6 SBOM, when parsed, then both spec versions are accepted", () => {
    expect(parseCycloneDx(cdx("1.4"), "bom.json", "sha").format).toBe("cyclonedx-1.4");
    expect(parseCycloneDx(cdx("1.6"), "bom.json", "sha").format).toBe("cyclonedx-1.6");
  });

  test("given the cdx:npm:is-dev property, when parsed, then the component is dev-only", () => {
    const json = JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      components: [
        {
          name: "jest",
          version: "29.0.0",
          purl: "pkg:npm/jest@29.0.0",
          properties: [{ name: "cdx:npm:is-dev", value: "true" }],
        },
      ],
    });
    const r = parseCycloneDx(json, "bom.json", "sha");
    expect(r.components[0]?.devOnly).toBe(true);
    expect(r.hasDevMarkers).toBe(true);
  });

  test("given an SBOM without any dev markers, when parsed, then no component is dev-only (safe default)", () => {
    const r = parseCycloneDx(cdx("1.5"), "bom.json", "sha");
    expect(r.components.every((c) => !c.devOnly || c.name === "@types/lodash")).toBe(true);
    expect(r.hasDevMarkers).toBe(true); // the fixture has a scope marker
    const plain = parseCycloneDx(
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [{ name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" }],
      }),
      "bom.json",
      "sha",
    );
    expect(plain.hasDevMarkers).toBe(false);
    expect(plain.components[0]?.devOnly).toBe(false);
  });

  test("given the dependencies graph, when parsed, then it is carried for the supply path", () => {
    const r = parseCycloneDx(cdx("1.5"), "bom.json", "sha");
    expect(r.dependencies.length).toBe(2);
    expect(r.dependencies[1]?.dependsOn).toEqual(["pkg:npm/lodash@4.17.20"]);
  });

  test("given an unsupported spec version, when parsed, then a UsageError is thrown (exit 2)", () => {
    expect(() => parseCycloneDx(cdx("9.9" as "1.5"), "bom.json", "sha")).toThrow(UsageError);
  });

  test("given non-JSON input, when parsed, then a UsageError is thrown (exit 2)", () => {
    expect(() => parseCycloneDx("this is not json", "bom.json", "sha")).toThrow(UsageError);
  });
});
