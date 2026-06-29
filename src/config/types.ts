export type SwarmMode = "static" | "runtime" | "ci";

export type SwarmProvider = "openai" | "mock" | "local";

export type RiskLevel = "passive" | "safe-active" | "mock-destructive";

export interface AllowedTarget {
  type: "local" | "preview";
  urlPattern?: string;
}

export interface SkillsConfig {
  externalRepo: string;
  externalRef?: string;
  externalRoot: string;
  localApprovedRoot: string;
  draftRoot: string;
  rejectedRoot: string;
  lockfile: string;
  autoSync?: boolean;
  autoReindex?: boolean;
}

export interface SwarmConfig {
  projectName: string;
  mode: SwarmMode;
  provider: SwarmProvider;
  model: string;
  riskLevel: RiskLevel;
  allowedTargets: AllowedTarget[];
  appCommand: string | null;
  appUrl?: string | null;
  skills: SkillsConfig;
  cacheDir: string;
  outputDir: string;
}

export interface InitResult {
  configPath: string;
  configCreated: boolean;
  directoriesCreated: string[];
}

export interface FolderStatus {
  path: string;
  exists: boolean;
}

export interface ResolvedProvider {
  provider: SwarmProvider;
  model: string;
  openaiKeyPresent: boolean;
  sources: {
    provider: "cli" | "config" | "env" | "default";
    model: "cli" | "config" | "env" | "default";
  };
}

export interface DoctorConfigStatus {
  configPath: string;
  exists: boolean;
  valid: boolean;
  message: string;
  execution: string | null;
  folders: FolderStatus[];
  provider: ResolvedProvider | null;
}
