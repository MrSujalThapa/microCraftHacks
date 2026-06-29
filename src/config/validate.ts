import type { RiskLevel, SwarmConfig, SwarmMode, SwarmProvider } from "./types";

const MODES = new Set<SwarmMode>(["static", "runtime", "ci"]);
const PROVIDERS = new Set<SwarmProvider>(["openai", "mock", "local"]);
const RISK_LEVELS = new Set<RiskLevel>(["passive", "safe-active", "mock-destructive"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, field: string, errors: string[]): value is string {
  if (typeof value !== "string") {
    errors.push(`${field} must be a string`);
    return false;
  }
  return true;
}

function requireEnum<T extends string>(
  value: unknown,
  field: string,
  allowed: Set<T>,
  errors: string[],
): value is T {
  if (typeof value !== "string" || !allowed.has(value as T)) {
    errors.push(`${field} must be one of: ${[...allowed].join(", ")}`);
    return false;
  }
  return true;
}

export function validateConfig(raw: unknown): SwarmConfig {
  const errors: string[] = [];

  if (!isRecord(raw)) {
    throw new Error("Config root must be an object");
  }

  if (!requireString(raw.projectName, "projectName", errors)) {
    /* collected */
  }
  requireEnum(raw.mode, "mode", MODES, errors);
  requireEnum(raw.provider, "provider", PROVIDERS, errors);
  if (!requireString(raw.model, "model", errors)) {
    /* collected */
  }
  requireEnum(raw.riskLevel, "riskLevel", RISK_LEVELS, errors);

  if (!Array.isArray(raw.allowedTargets) || raw.allowedTargets.length === 0) {
    errors.push("allowedTargets must be a non-empty array");
  }

  if (raw.appCommand !== null && typeof raw.appCommand !== "string") {
    errors.push("appCommand must be a string or null");
  }

  if (
    raw.appUrl !== undefined &&
    raw.appUrl !== null &&
    typeof raw.appUrl !== "string"
  ) {
    errors.push("appUrl must be a string, null, or omitted");
  }

  if (!requireString(raw.cacheDir, "cacheDir", errors)) {
    /* collected */
  }
  if (!requireString(raw.outputDir, "outputDir", errors)) {
    /* collected */
  }

  if (!isRecord(raw.skills)) {
    errors.push("skills must be an object");
  } else {
    requireString(raw.skills.externalRepo, "skills.externalRepo", errors);
    requireString(raw.skills.externalRoot, "skills.externalRoot", errors);
    requireString(raw.skills.localApprovedRoot, "skills.localApprovedRoot", errors);
    requireString(raw.skills.draftRoot, "skills.draftRoot", errors);
    requireString(raw.skills.rejectedRoot, "skills.rejectedRoot", errors);
    requireString(raw.skills.lockfile, "skills.lockfile", errors);
  }

  if (errors.length > 0) {
    throw new Error(errors.join("; "));
  }

  return raw as unknown as SwarmConfig;
}
