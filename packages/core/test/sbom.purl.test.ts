import { describe, expect, test } from "bun:test";
import { isNpmPurl, parsePurl } from "../src/sbom/purl.js";
import { UsageError } from "../src/util/errors.js";

describe("purl parsing (plan 5.1)", () => {
  test("given an npm purl, when parsed, then name and version are extracted", () => {
    const p = parsePurl("pkg:npm/lodash@4.17.20");
    expect(p.type).toBe("npm");
    expect(p.name).toBe("lodash");
    expect(p.version).toBe("4.17.20");
  });

  test("given a scoped npm purl, when parsed, then the scope percent-encoding is decoded", () => {
    const p = parsePurl("pkg:npm/%40babel/core@7.20.0");
    expect(p.name).toBe("@babel/core");
    expect(p.version).toBe("7.20.0");
  });

  test("given a purl without a version, when parsed, then the version is absent", () => {
    const p = parsePurl("pkg:npm/express");
    expect(p.name).toBe("express");
    expect(p.version).toBeUndefined();
  });

  test("given a non-npm purl, when classified, then it is not npm", () => {
    expect(isNpmPurl("pkg:maven/org.apache/httpclient@4.5.13")).toBe(false);
    expect(isNpmPurl("pkg:npm/express@4.18.2")).toBe(true);
  });

  test("given a malformed purl, when parsed, then a UsageError is thrown (exit 2)", () => {
    expect(() => parsePurl("not-a-purl")).toThrow(UsageError);
    expect(() => parsePurl("pkg:npm/foo@1.0.0?qualifier=1")).toThrow(UsageError);
  });

  test("given a purl whose name part contains @, when parsed, then the LAST @ splits the version (purl spec)", () => {
    const p = parsePurl("pkg:npm/somepkg@file:dep@1.0.0");
    expect(p.name).toBe("somepkg@file:dep");
    expect(p.version).toBe("1.0.0");
  });
});
