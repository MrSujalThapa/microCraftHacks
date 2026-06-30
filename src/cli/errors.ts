import { ConfigError } from "../config/errors";
import { ProviderError } from "../config/provider-errors";
import { AgentRuntimeError } from "../agents/runtime";
import { FindingsError } from "../findings/errors";
import { SkillsError } from "../skills/errors";

function printProcessOutput(label: string, text: string): void {
  const trimmed = text.trim();
  if (!trimmed) {
    return;
  }
  console.error(`${label}:`);
  console.error(trimmed);
}

export function printCliError(error: unknown): void {
  if (error instanceof AgentRuntimeError) {
    console.error(`Error: ${error.message}`);
    printProcessOutput("Python stdout", error.stdout);
    printProcessOutput("Python stderr", error.stderr);
    return;
  }
  if (error instanceof ConfigError) {
    console.error(`Error: ${error.message}`);
    if (error.code === "MISSING") {
      console.error("Run `swarm init` to create the default config and folders.");
    }
    return;
  }

  if (error instanceof SkillsError) {
    console.error(`Error: ${error.message}`);
    return;
  }

  if (error instanceof FindingsError) {
    console.error(`Error: ${error.message}`);
    return;
  }

  if (error instanceof ProviderError) {
    console.error(`Error: ${error.message}`);
    return;
  }

  if (error instanceof Error) {
    console.error(`Error: ${error.message}`);
    return;
  }

  console.error("Error: unexpected failure");
}

export function runWithCliErrors(action: () => void): void {
  try {
    action();
  } catch (error) {
    printCliError(error);
    process.exitCode = 1;
  }
}
