import { printCliError } from "./errors";
import { runExplainCommand, runFindingsCommand } from "../findings";

export function runFindingsListCommand(options: { report?: string }): void {
  try {
    runFindingsCommand(options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}

export function runFindingsExplainCommand(
  findingId: string,
  options: { report?: string },
): void {
  try {
    runExplainCommand(findingId, options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
