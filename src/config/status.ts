import { existsSync } from "node:fs";
import { join } from "node:path";

import { ConfigError } from "./errors";
import { loadConfig } from "./load";
import { getConfigPath, getManagedDirectories } from "./paths";
import type { DoctorConfigStatus } from "./types";

export function getDoctorConfigStatus(root = process.cwd()): DoctorConfigStatus {
  const configPath = getConfigPath(root);
  const exists = existsSync(configPath);

  if (!exists) {
    return {
      configPath,
      exists: false,
      valid: false,
      message: "missing — run `swarm init`",
      execution: null,
      folders: [],
    };
  }

  try {
    const config = loadConfig(root);
    const folders = getManagedDirectories(config).map((path) => ({
      path,
      exists: existsSync(join(root, path)),
    }));

    return {
      configPath,
      exists: true,
      valid: true,
      message: "ok",
      execution: `${config.riskLevel} / ${config.provider} (${config.model})`,
      folders,
    };
  } catch (error) {
    const message =
      error instanceof ConfigError
        ? error.message
        : error instanceof Error
          ? error.message
          : "invalid config";

    return {
      configPath,
      exists: true,
      valid: false,
      message,
      execution: null,
      folders: [],
    };
  }
}
