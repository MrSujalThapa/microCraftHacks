import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ENV_FILE_NAME = ".env";

export function loadDotEnv(root = process.cwd()): boolean {
  const envPath = join(root, ENV_FILE_NAME);
  if (!existsSync(envPath)) {
    return false;
  }

  const content = readFileSync(envPath, "utf8");
  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const separator = line.indexOf("=");
    if (separator <= 0) {
      continue;
    }

    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }

  return true;
}

export function isOpenAiKeyPresent(): boolean {
  const value = process.env.OPENAI_API_KEY?.trim();
  return Boolean(value);
}

export function readEnvProvider(): string | undefined {
  const value = process.env.SWARM_PROVIDER?.trim();
  return value || undefined;
}

export function readEnvModel(): string | undefined {
  const value = process.env.SWARM_MODEL?.trim();
  return value || undefined;
}
