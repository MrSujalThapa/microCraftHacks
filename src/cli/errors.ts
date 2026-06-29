import { FindingsError } from "../findings/errors";
import { ConfigError } from "../config/errors";
import { SkillsError } from "../skills/errors";

export function printCliError(error: unknown): void {
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
