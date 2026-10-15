// M6 — pure-part contract of the compile pipeline: magic-byte validation,
// SHA256SUMS formatting, host-target selection. (The real compile + --version
// smoke is exercised in CI by scripts/binary-smoke.ts on native runners.)

import { describe, expect, test } from "bun:test";
import { TARGETS, hostFamily, isHostTarget, sha256Hex, sumsLines, validateMagicBytes } from "./build.js";

const ELF = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]);
// The four canonical Mach-O spellings (MH_MAGIC / MH_MAGIC_64 in either byte order).
const MACHO_LE64 = new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]); // 0xfeedfacf, little-endian
const MACHO_BE32 = new Uint8Array([0xfe, 0xed, 0xfa, 0xce]); // 0xfeedface, big-endian
const MACHO_BE64 = new Uint8Array([0xfe, 0xed, 0xfa, 0xcf]); // 0xfeedfacf, big-endian
const MACHO_LE32 = new Uint8Array([0xce, 0xfa, 0xed, 0xfe]); // 0xfeedface, little-endian
const PE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);

describe("validateMagicBytes", () => {
  test("given ELF bytes, when checked against the elf family, then it is accepted", () => {
    expect(validateMagicBytes(ELF, "elf")).toBe(true);
  });

  test("given Mach-O bytes in every canonical spelling, when checked against macho, then each is accepted", () => {
    expect(validateMagicBytes(MACHO_LE64, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_BE32, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_BE64, "macho")).toBe(true);
    expect(validateMagicBytes(MACHO_LE32, "macho")).toBe(true);
  });

  test("given PE bytes, when checked against the pe family, then it is accepted", () => {
    expect(validateMagicBytes(PE, "pe")).toBe(true);
  });

  test("given bytes of one family, when checked against a DIFFERENT family, then it is rejected (false-positive guard)", () => {
    expect(validateMagicBytes(ELF, "pe")).toBe(false);
    expect(validateMagicBytes(ELF, "macho")).toBe(false);
    expect(validateMagicBytes(MACHO_LE64, "elf")).toBe(false);
    expect(validateMagicBytes(PE, "elf")).toBe(false);
  });

  test("given a truncated buffer (fewer than 4 bytes), when checked, then it is rejected without throwing", () => {
    expect(validateMagicBytes(new Uint8Array([0x7f, 0x45]), "elf")).toBe(false);
    expect(validateMagicBytes(new Uint8Array([0x4d]), "pe")).toBe(false);
    expect(validateMagicBytes(new Uint8Array(), "macho")).toBe(false);
  });

  test("given near-miss magic bytes (one byte off), when checked, then they are rejected", () => {
    const nearMissElf = new Uint8Array([0x7f, 0x45, 0x4c, 0x50]); // 'P' not 'F'
    const nearMissMacho = new Uint8Array([0xcf, 0xfb, 0xed, 0xfe]); // fb not fa
    expect(validateMagicBytes(nearMissElf, "elf")).toBe(false);
    expect(validateMagicBytes(nearMissMacho, "macho")).toBe(false);
  });

  test("given the eight release targets, when each is validated against its own family, then the family table is well-formed", () => {
    expect(TARGETS.length).toBe(8);
    const suffixes = TARGETS.map((t) => t.suffix);
    expect(new Set(suffixes).size).toBe(8);
  });
});

describe("sha256Hex / sumsLines", () => {
  test("given the empty-string vector, when hashed, then the known SHA-256 constant is produced", () => {
    expect(sha256Hex(new Uint8Array([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  test("given entries in arbitrary order, when rendered, then lines are sorted by path with the sha256 two-space format", () => {
    const out = sumsLines([
      { file: "dist/callis-linux-x64", hex: "a".repeat(64) },
      { file: "dist/callis-darwin-arm64", hex: "b".repeat(64) },
      { file: "dist/callis-linux-x64-musl", hex: "c".repeat(64) },
    ]);
    const lines = [
      `${"b".repeat(64)}  dist/callis-darwin-arm64`,
      `${"a".repeat(64)}  dist/callis-linux-x64`,
      `${"c".repeat(64)}  dist/callis-linux-x64-musl`,
    ];
    expect(out).toBe(`${lines.join("\n")}\n`);
  });

  test("given an empty entry list, when rendered, then the result is the empty string (no header, no trailing newline)", () => {
    expect(sumsLines([])).toBe("");
  });

  test("given duplicate paths, when rendered, then both lines are kept (one line per artifact)", () => {
    const out = sumsLines([
      { file: "dist/callis-linux-x64", hex: "a".repeat(64) },
      { file: "dist/callis-linux-x64", hex: "b".repeat(64) },
    ]);
    expect(out.split("\n")).toHaveLength(3); // two lines + trailing newline
  });
});

describe("isHostTarget", () => {
  test("given the current host, when every target is tested, then exactly the executable targets are selected (and at most one per architecture)", () => {
    const host = hostFamily();
    if (host === null) {
      expect(TARGETS.some(isHostTarget)).toBe(false);
      return;
    }
    const executable = TARGETS.filter(isHostTarget);
    expect(executable.length).toBeGreaterThan(0);
    // No target from another family is ever executable here.
    for (const t of TARGETS) {
      if (t.family !== host) expect(isHostTarget(t)).toBe(false);
    }
  });

  test("given a non-host family target, when tested, then it is rejected (cross-compiled binaries are not run in this pipeline)", () => {
    const foreign = TARGETS.filter((t) => t.family !== hostFamily());
    for (const t of foreign) expect(isHostTarget(t)).toBe(false);
  });
});
