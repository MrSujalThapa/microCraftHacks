import { printCliError } from "./errors";
import { runAgentsCommand } from "../agents";

export function runAgentsRunCommand(options: {
  report: string;
  routedSkills?: string;
  output?: string;
}): void {
  try {
    runAgentsCommand(options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
