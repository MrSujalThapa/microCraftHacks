import { existsSync, readFileSync } from "node:fs";

export interface ActivationSummary {
  skillsRouted: number;
  agentsPlanned: number;
  agentsRun: number;
  agentTypes: string[];
  findingsVerified: number;
  findingsRejected: number;
}

export function readRoutedSkillsCount(routedSkillsPath: string): number {
  if (!existsSync(routedSkillsPath)) {
    return 0;
  }
  try {
    const payload = JSON.parse(readFileSync(routedSkillsPath, "utf8")) as {
      selected?: unknown[];
    };
    return Array.isArray(payload.selected) ? payload.selected.length : 0;
  } catch {
    return 0;
  }
}

export function readActivationSummary(
  findingsPath: string,
  fallbackSkillsRouted = 0,
): ActivationSummary {
  const fallback: ActivationSummary = {
    skillsRouted: fallbackSkillsRouted,
    agentsPlanned: 0,
    agentsRun: 0,
    agentTypes: [],
    findingsVerified: 0,
    findingsRejected: 0,
  };

  if (!existsSync(findingsPath)) {
    return fallback;
  }

  try {
    const payload = JSON.parse(readFileSync(findingsPath, "utf8")) as {
      verifiedFindings?: unknown[];
      rejectedFindings?: unknown[];
      metrics?: {
        activation?: Partial<ActivationSummary>;
        summary?: {
          verifiedCount?: number;
          rejectedCount?: number;
        };
      };
    };

    const activation = payload.metrics?.activation;
    if (activation) {
      return {
        skillsRouted: activation.skillsRouted ?? fallbackSkillsRouted,
        agentsPlanned: activation.agentsPlanned ?? 0,
        agentsRun: activation.agentsRun ?? 0,
        agentTypes: activation.agentTypes ?? [],
        findingsVerified:
          activation.findingsVerified ??
          payload.metrics?.summary?.verifiedCount ??
          (payload.verifiedFindings?.length ?? 0),
        findingsRejected:
          activation.findingsRejected ??
          payload.metrics?.summary?.rejectedCount ??
          (payload.rejectedFindings?.length ?? 0),
      };
    }

    return {
      ...fallback,
      findingsVerified:
        payload.metrics?.summary?.verifiedCount ?? (payload.verifiedFindings?.length ?? 0),
      findingsRejected:
        payload.metrics?.summary?.rejectedCount ?? (payload.rejectedFindings?.length ?? 0),
    };
  } catch {
    return fallback;
  }
}

export function printActivationSummary(summary: ActivationSummary): void {
  console.log("");
  console.log("Activation summary (skills ≠ agents):");
  console.log(`  skillsRouted: ${summary.skillsRouted}`);
  console.log(`  agentsPlanned: ${summary.agentsPlanned}`);
  console.log(`  agentsRun: ${summary.agentsRun}`);
  console.log(
    `  agentTypes: ${summary.agentTypes.length > 0 ? summary.agentTypes.join(", ") : "none"}`,
  );
  console.log(`  findingsVerified: ${summary.findingsVerified}`);
  console.log(`  findingsRejected: ${summary.findingsRejected}`);
}
