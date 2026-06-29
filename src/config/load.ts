import { existsSync, readFileSync } from "node:fs";

import { ConfigError } from "./errors";
import { getConfigPath } from "./paths";
import { validateConfig } from "./validate";
import type { SwarmConfig } from "./types";

export function loadConfig(root = process.cwd()): SwarmConfig {
  const configPath = getConfigPath(root);

  if (!existsSync(configPath)) {
    throw new ConfigError(
      `Config not found at ${configPath}`,
      "MISSING",
      configPath,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, "utf8")) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid JSON";
    throw new ConfigError(
      `Config at ${configPath} is not valid JSON: ${detail}`,
      "PARSE",
      configPath,
    );
  }

  try {
    return validateConfig(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid config";
    throw new ConfigError(
      `Config at ${configPath} is invalid: ${detail}`,
      "INVALID",
      configPath,
    );
  }
}

export function tryLoadConfig(root = process.cwd()): SwarmConfig | null {
  try {
    return loadConfig(root);
  } catch (error) {
    if (error instanceof ConfigError) {
      return null;
    }
    throw error;
  }
}
