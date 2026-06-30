export class FindingsError extends Error {
  constructor(
    message: string,
    readonly code: "MISSING" | "NOT_FOUND" | "INVALID" = "NOT_FOUND",
  ) {
    super(message);
    this.name = "FindingsError";
  }
}
