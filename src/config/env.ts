import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ENV_FILE_NAME = ".env";
export const ENV_RELATIVE_PATH = ENV_FILE_NAME;

const CYBER_SWARM_ENV_KEYS = new Set([
  "OPENAI_API_KEY",
  "SWARM_PROVIDER",
  "SWARM_MODEL",
]);

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

export function readOpenAiKey(root = process.cwd()): string | undefined {
  loadDotEnv(root);
  const value = process.env.OPENAI_API_KEY?.trim();
  return value || undefined;
}

export function readEnvProvider(): string | undefined {
  const value = process.env.SWARM_PROVIDER?.trim();
  return value || undefined;
}

export function readEnvModel(): string | undefined {
  const value = process.env.SWARM_MODEL?.trim();
  return value || undefined;
}

function quoteEnvValue(value: string): string {
  if (/^[A-Za-z0-9_./:@+\-=]+$/u.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

export function upsertDotEnvValues(
  root = process.cwd(),
  values: Partial<Record<"OPENAI_API_KEY" | "SWARM_PROVIDER" | "SWARM_MODEL", string>>,
): string {
  const envPath = join(root, ENV_FILE_NAME);
  const existing = existsSync(envPath) ? readFileSync(envPath, "utf8") : "";
  const hadTrailingNewline = existing.length === 0 || /\r?\n$/u.test(existing);
  const lines = existing.length > 0 ? existing.replace(/\r?\n$/u, "").split(/\r?\n/u) : [];
  const seen = new Set<string>();

  const updatedLines = lines.map((rawLine) => {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      return rawLine;
    }

    const separator = rawLine.indexOf("=");
    if (separator <= 0) {
      return rawLine;
    }

    const key = rawLine.slice(0, separator).trim();
    if (!CYBER_SWARM_ENV_KEYS.has(key) || values[key as keyof typeof values] === undefined) {
      return rawLine;
    }

    seen.add(key);
    const value = values[key as keyof typeof values]!;
    return `${key}=${quoteEnvValue(value)}`;
  });

  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && !seen.has(key)) {
      updatedLines.push(`${key}=${quoteEnvValue(value)}`);
    }
  }

  const content = `${updatedLines.join("\n")}${hadTrailingNewline ? "\n" : ""}`;
  writeFileSync(envPath, content, "utf8");

  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) {
      process.env[key] = value;
    }
  }

  return envPath;
}
