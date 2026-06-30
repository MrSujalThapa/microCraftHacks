import { printCliError } from "./errors";
import { runDemoCommand } from "../demo";

export function runDemoCliCommand(options: {
  target?: string;
  provider?: "openai" | "mock" | "local";
  model?: string;
  fromCache?: boolean;
  latency?: "fastest" | "balanced" | "thorough";
  noLlm?: boolean;
  forceLlm?: boolean;
}): void {
  try {
    runDemoCommand(options);
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
