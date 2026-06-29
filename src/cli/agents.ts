import { printCliError } from "./errors";
import { runAgentsCommand } from "../agents";

export function runAgentsRunCommand(options: {
  report: string;
  routedSkills?: string;
  output?: string;
  provider?: "openai" | "mock" | "local";
  model?: string;
}): void {
  try {
    runAgentsCommand(options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
