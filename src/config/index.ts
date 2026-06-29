export { createDefaultConfig } from "./defaults";
export { ConfigError } from "./errors";
export { initProject } from "./init";
export { loadConfig, tryLoadConfig } from "./load";
export { CONFIG_RELATIVE_PATH, DEFAULT_PATHS, getConfigPath, getManagedDirectories } from "./paths";
export { getDoctorConfigStatus } from "./status";
export type {
  AllowedTarget,
  DoctorConfigStatus,
  FolderStatus,
  InitResult,
  RiskLevel,
  SkillsConfig,
  SwarmConfig,
  SwarmMode,
  SwarmProvider,
} from "./types";
export { validateConfig } from "./validate";
