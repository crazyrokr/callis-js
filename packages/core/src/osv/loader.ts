// OSV snapshot loading (plan sections 5.2, 6).
//
// The directory must exist and be readable (exit 2). A directory with files
// but zero VALID records is an analysis failure (exit 3) — the snapshot
// parsed to nothing. --osv-checksum mismatch or hash failure is exit 2
// (JVM parity).

import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { UsageError } from "../util/errors.js";
import { computePin } from "./checksum.js";
import { type OsvIndex, filesForPackages, listRecordFiles, loadIndex } from "./index-store.js";
import { type OsRecord, type ReadRecordFn, defaultReadRecord, readRecordFile } from "./record.js";

export interface OsvSnapshot {
  dir: string;
  pin: string;
  index: OsvIndex;
  /** Records for the SBOM package set (normalized inputs). */
  records: OsRecord[];
  /** Records that failed schema validation (skipped + counted). */
  skippedRecords: number;
  /** True when the directory had record files but zero valid records. */
  zeroValidRecords: boolean;
}

export async function loadSnapshot(
  osvDir: string,
  packageNames: string[],
  cacheDir: string,
  expectedPin?: string,
  read: ReadRecordFn = defaultReadRecord,
): Promise<OsvSnapshot> {
  // The directory must exist and be readable (exit 2). A directory with
  // record FILES but zero valid records is the exit-3 condition — anyFile
  // counts recursive .json files (a .gitkeep or other file is not a record).
  let anyFile = false;
  try {
    await readdir(osvDir, { withFileTypes: true });
    anyFile = (await listRecordFiles(osvDir)).length > 0;
  } catch (e) {
    throw new UsageError(`OSV directory not readable: ${osvDir}: ${(e as Error).message}`);
  }
  const pin = await computePin(osvDir);
  if (expectedPin !== undefined && expectedPin !== pin) {
    throw new UsageError(`OSV snapshot pin mismatch: expected ${expectedPin}, computed ${pin}`);
  }
  const index = await loadIndex(osvDir, pin, cacheDir, read);
  const files = anyFile ? filesForPackages(index, packageNames) : [];
  const records: OsRecord[] = [];
  let skipped = index.skippedRecords;
  for (const f of files) {
    const record = await readRecordFile(join(osvDir, f), read);
    if (record === null || record.id.length === 0) skipped += 1;
    else records.push(record);
  }
  // Files-but-zero-valid-records is the exit-3 condition (plan section 6).
  const zeroValidRecords = anyFile && index.validRecords === 0;
  return { dir: osvDir, pin, index, records, skippedRecords: skipped, zeroValidRecords };
}
