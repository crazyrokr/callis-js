// Typed error classes. The policy layer maps these to exit codes
// (plan section 6: precedence 2 > 3 > 1 > 0).

/** Usage or configuration error — exit 2 (malformed input, bad flags, ...). */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

/** Analysis failure — exit 3 (guards fired, graph build failed, ...). */
export class AnalysisFailure extends Error {
  /** True when a minimal report must still be written (guard failures). */
  public readonly reportable: boolean;
  constructor(message: string, reportable = false) {
    super(message);
    this.name = "AnalysisFailure";
    this.reportable = reportable;
  }
}

/** A finding-level diagnostic surfaced in the report, never an error. */
export interface Notice {
  code: string;
  message: string;
  purl?: string;
  advisoryId?: string;
}
