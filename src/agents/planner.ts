import { isTestFile } from "../shared/files";
import type { ScanReport } from "../scanner/types";

export interface PlannedAgent {
  agentType: string;
  specialist: string;
  reasons: string[];
}

export const SPECIALIST_BY_AGENT_TYPE: Record<string, string> = {
  auth: "auth-breaker",
  api: "api-abuse",
  secrets: "secrets-config",
  dependency: "secrets-config",
  storage: "api-abuse",
  ai: "secrets-config",
  config: "secrets-config",
};

const DEPENDENCY_MANIFESTS = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "go.mod",
  "cargo.toml",
  "composer.json",
]);

const CONFIG_PATH_TOKENS = [".env", "config", "secret", "settings"];

const AI_TOKENS = ["openai", "anthropic", "langchain", "llm", "gpt", "claude", "embedding"];

const STORAGE_TOKENS = ["supabase", "s3", "storage", "blob", "upload", "bucket"];

function basename(path: string): string {
  return path.replace(/\\/g, "/").split("/").pop() ?? path;
}

function isProductionPath(path: string): boolean {
  return !isTestFile(path);
}

function hasWebApiAuthSurfaces(report: ScanReport): boolean {
  const surfaces = report.surfaces ?? { routes: [], api: [], auth: [], dataModels: [] };
  const authFiles = surfaces.auth.filter((auth) => isProductionPath(auth.file));
  const apiRoutes = [...surfaces.routes, ...surfaces.api].filter((route) =>
    isProductionPath(route.file),
  );
  return authFiles.length > 0 || apiRoutes.length > 0;
}

function detectDependencySignals(report: ScanReport): string[] {
  const reasons: string[] = [];
  for (const file of report.inventory.files) {
    if (isTestFile(file.path)) {
      continue;
    }
    const name = basename(file.path).toLowerCase();
    if (DEPENDENCY_MANIFESTS.has(name)) {
      reasons.push(`dependency manifest: ${file.path}`);
    }
  }
  return reasons;
}

function detectConfigSignals(report: ScanReport): string[] {
  const reasons: string[] = [];
  for (const file of report.inventory.files) {
    if (isTestFile(file.path)) {
      continue;
    }
    if (file.category !== "config" && file.category !== "json" && file.category !== "yaml") {
      continue;
    }
    const lower = file.path.toLowerCase();
    if (CONFIG_PATH_TOKENS.some((token) => lower.includes(token))) {
      reasons.push(`config surface: ${file.path}`);
    }
  }
  return reasons;
}

function detectStorageSignals(report: ScanReport): string[] {
  const reasons: string[] = [];
  for (const stack of report.stack ?? []) {
    const lower = stack.name.toLowerCase();
    if (STORAGE_TOKENS.some((token) => lower.includes(token))) {
      reasons.push(`stack: ${stack.name}`);
    }
  }
  const surfaces = report.surfaces ?? { routes: [], api: [], auth: [], dataModels: [] };
  for (const route of [...surfaces.routes, ...surfaces.api]) {
    if (!isProductionPath(route.file)) {
      continue;
    }
    const lower = route.path.toLowerCase();
    if (STORAGE_TOKENS.some((token) => lower.includes(token))) {
      reasons.push(`storage route: ${route.path}`);
    }
  }
  return reasons;
}

function detectAiSignals(report: ScanReport): string[] {
  const reasons: string[] = [];
  for (const stack of report.stack ?? []) {
    const corpus = `${stack.name} ${stack.evidence.join(" ")}`.toLowerCase();
    if (AI_TOKENS.some((token) => corpus.includes(token))) {
      reasons.push(`stack: ${stack.name}`);
    }
  }
  for (const file of report.inventory.files) {
    if (isTestFile(file.path)) {
      continue;
    }
    const normalized = file.path.replace(/\\/g, "/").toLowerCase();
    if (normalized.includes("__pycache__") || normalized.endsWith(".pyc")) {
      continue;
    }
    if (AI_TOKENS.some((token) => normalized.includes(token))) {
      reasons.push(`ai-related path: ${file.path}`);
    }
  }
  return reasons;
}

export function planAgentsFromScanReport(report: ScanReport): PlannedAgent[] {
  const surfaces = report.surfaces ?? { routes: [], api: [], auth: [], dataModels: [] };
  const planned = new Map<string, PlannedAgent>();

  const addAgent = (agentType: string, reason: string): void => {
    const specialist = SPECIALIST_BY_AGENT_TYPE[agentType];
    if (!specialist) {
      return;
    }
    const existing = planned.get(agentType);
    if (existing) {
      if (!existing.reasons.includes(reason)) {
        existing.reasons.push(reason);
      }
      return;
    }
    planned.set(agentType, { agentType, specialist, reasons: [reason] });
  };

  for (const auth of surfaces.auth) {
    if (isProductionPath(auth.file)) {
      addAgent("auth", `auth surface: ${auth.file}`);
    }
  }

  for (const route of [...surfaces.routes, ...surfaces.api]) {
    if (!isProductionPath(route.file)) {
      continue;
    }
    addAgent("api", `route: ${route.path}`);
  }

  for (const reason of detectConfigSignals(report)) {
    addAgent("secrets", reason);
  }

  for (const reason of detectDependencySignals(report)) {
    addAgent("dependency", reason);
  }

  for (const reason of detectStorageSignals(report)) {
    addAgent("storage", reason);
  }

  for (const reason of detectAiSignals(report)) {
    addAgent("ai", reason);
  }

  if (planned.size === 0 || !hasWebApiAuthSurfaces(report)) {
    if (!hasWebApiAuthSurfaces(report)) {
      planned.clear();
      for (const reason of detectConfigSignals(report)) {
        addAgent("config", reason);
        addAgent("secrets", reason);
      }
      if (planned.size === 0) {
        addAgent("config", "CLI/config-only repo: default config agent");
        addAgent("secrets", "CLI/config-only repo: default secrets agent");
      }
      for (const reason of detectDependencySignals(report)) {
        addAgent("dependency", reason);
      }
      if (!planned.has("dependency")) {
        addAgent("dependency", "CLI/config-only repo: default dependency agent");
      }
    }
  }

  return [...planned.values()].sort((a, b) => a.agentType.localeCompare(b.agentType));
}

export function countUniqueSpecialists(agents: PlannedAgent[]): number {
  return new Set(agents.map((agent) => agent.specialist)).size;
}
