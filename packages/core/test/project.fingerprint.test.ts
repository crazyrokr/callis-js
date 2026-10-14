// M2 — install fingerprint (plan section 5.3, ADRs 0014/0015).

import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { installFingerprint, readStateFiles } from "../src/project/fingerprint.js";
import type { PackageInstance } from "../src/project/types.js";
import { byteOrderSort, sha256Hex } from "../src/util/hash.js";
import { mkFixture, pkg } from "./project.fixtures.js";

function inst(name: string, version: string, relPath: string): PackageInstance {
  return {
    name,
    version,
    realDir: `/proj/${relPath}`,
    relPath,
    library: true,
    parent: null,
    pkgType: "commonjs",
  };
}

describe("install fingerprint (ADR 0014)", () => {
  test("given the same instances in different order, when fingerprinted, then the hash is identical (byte-order sort, never localeCompare)", () => {
    const a = [
      inst("a", "1.0.0", "node_modules/a"),
      inst("z", "1.0.0", "node_modules/z"),
      inst("m", "2.0.0", "node_modules/m"),
    ];
    const b = [...a].reverse();
    expect(installFingerprint(a, [], [])).toBe(installFingerprint(b, [], []));
    expect(installFingerprint(a, [], [])).toMatch(/^[0-9a-f]{64}$/);
  });

  test("given a drift in one instance (version change), when fingerprinted, then the hash changes", () => {
    const before = [inst("a", "1.0.0", "node_modules/a")];
    const after = [inst("a", "1.0.1", "node_modules/a")];
    expect(installFingerprint(before, [], [])).not.toBe(installFingerprint(after, [], []));
  });

  test("given a patched realpath (same name+version, different dir), when fingerprinted, then the hash changes", () => {
    const before = [inst("a", "1.0.0", "node_modules/a")];
    const after = [inst("a", "1.0.0", "node_modules/a-patched")];
    expect(installFingerprint(before, [], [])).not.toBe(installFingerprint(after, [], []));
  });

  test("given install-state files, when fingerprinted, then their content hashes join the key", () => {
    const instances = [inst("a", "1.0.0", "node_modules/a")];
    const path = "/proj/node_modules/.package-lock.json";
    const content = JSON.stringify({ name: "app" });
    const withState = installFingerprint(instances, [{ path, sha256: sha256Hex(content) }], [path]);
    const withoutState = installFingerprint(instances, [], [path]);
    const noExpectation = installFingerprint(instances, [], []);
    expect(withState).not.toBe(withoutState);
    expect(withState).not.toBe(noExpectation);
  });

  test("given a missing install-state file, when fingerprinted, then the absence is visible (dash marker, distinct from present)", () => {
    const instances = [inst("a", "1.0.0", "node_modules/a")];
    const path = "/proj/node_modules/.package-lock.json";
    const absent = installFingerprint(instances, [], [path]);
    const present = installFingerprint(instances, [{ path, sha256: "b".repeat(64) }], [path]);
    expect(absent).not.toBe(present);
  });

  test("given a real project with a .package-lock.json, when read, then the state file is captured with its content hash", async () => {
    const root = await mkFixture({
      files: {
        "package.json": pkg("app", "1.0.0"),
        "node_modules/.package-lock.json": JSON.stringify({ name: "app" }),
        "node_modules/a/package.json": pkg("a", "1.0.0"),
      },
    });
    const files = readStateFiles(root, "npm");
    expect(files.length).toBe(1);
    expect(files[0]?.path).toBe(join(root, "node_modules", ".package-lock.json"));
    expect(files[0]?.sha256).toBe(sha256Hex(JSON.stringify({ name: "app" })));
  });

  test("given a project without state files, when read, then the list is empty (not an error)", async () => {
    const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0") } });
    expect(readStateFiles(root, "npm")).toEqual([]);
  });

  test("given an unreadable state file path, when read, then it is skipped (the absence is recorded by the fingerprint)", async () => {
    const root = await mkFixture({ files: { "package.json": pkg("app", "1.0.0") } });
    expect(readStateFiles(join(root, "does-not-exist"), "npm")).toEqual([]);
  });

  test("given the pin algorithm, when compared with the OSV byte-order sort, then the same utility is used (no divergence)", () => {
    const lines = ["inst b@1 node_modules/b", "inst a@1 node_modules/a"];
    expect(byteOrderSort(lines)).toEqual(["inst a@1 node_modules/a", "inst b@1 node_modules/b"]);
  });
});
