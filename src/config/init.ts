import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { createDefaultConfig } from "./defaults";
import { loadConfig } from "./load";
import { getConfigPath, getManagedDirectories } from "./paths";
import type { InitResult, SwarmConfig } from "./types";

function ensureDirectories(root: string, config: SwarmConfig): string[] {
  const directoriesCreated: string[] = [];

  for (const relativePath of getManagedDirectories(config)) {
    const target = join(root, relativePath);
    if (!existsSync(target)) {
      mkdirSync(target, { recursive: true });
      directoriesCreated.push(relativePath);
    }
  }

  return directoriesCreated;
}

export function initProject(root = process.cwd()): InitResult {
  const configPath = getConfigPath(root);
  const configExists = existsSync(configPath);
  let configCreated = false;
  let config: SwarmConfig;

  if (configExists) {
    try {
      config = loadConfig(root);
    } catch {
      config = createDefaultConfig(root);
    }
  } else {
    mkdirSync(dirname(configPath), { recursive: true });
    config = createDefaultConfig(root);
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    configCreated = true;
  }

  const directoriesCreated = ensureDirectories(root, config);

  return {
    configPath,
    configCreated,
    directoriesCreated,
  };
}
