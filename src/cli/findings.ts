import { printCliError } from "./errors";
import { runExplainCommand, runFindingsCommand, runFixCommand } from "../findings";

export function runFindingsListCommand(options: { report?: string; demo?: boolean }): void {
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

export function runFindingsFixCommand(findingId: string, options: { report?: string }): void {
  try {
    runFixCommand(findingId, options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
