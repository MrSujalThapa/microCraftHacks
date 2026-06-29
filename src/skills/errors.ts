export type SkillsErrorCode = "MISSING_LOCKFILE" | "MISSING_INDEX" | "SYNC_FAILED" | "INVALID_REPORT";

export class SkillsError extends Error {
  readonly code: SkillsErrorCode;

  constructor(message: string, code: SkillsErrorCode) {
    super(message);
    this.name = "SkillsError";
    this.code = code;
  }
}
