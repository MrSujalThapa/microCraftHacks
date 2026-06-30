import { resolve } from "node:path";

import { deriveFindingsMarkdownPath } from "../findings/load";
import { planAgentsFromScanReport } from "./planner";
import { deriveFindingsOutputPath, resolveAgentRuntimePaths, runAgentRuntime } from "./runtime";
import {
  printActivationSummary,
  readActivationSummary,
  readRoutedSkillsCount,
} from "./summary";
import { readScanReport } from "../skills/router";

export function runAgentsCommand(options: {
  report: string;
  routedSkills?: string;
  output?: string;
  provider?: "openai" | "mock" | "local";
  model?: string;
  mode?: string;
  fromCache?: boolean;
}): void {
  const root = resolve(process.cwd());
  const paths = resolveAgentRuntimePaths(root, {
    reportPath: options.report,
    routedSkillsPath: options.routedSkills,
    outputPath: options.output,
  });

  const scanReport = readScanReport(paths.reportPath);
  const plannedAgents = planAgentsFromScanReport(scanReport);
  const skillsRouted = readRoutedSkillsCount(paths.routedSkillsPath);

  console.log("Specialist activation (playbooks supplement routing, not execution plan):");
  console.log(`  Planned specialists: ${plannedAgents.length}`);
  for (const agent of plannedAgents) {
    console.log(`    ${agent.specialist} — ${agent.reasons[0] ?? "surface match"}`);
  }
  console.log(`  Playbooks routed (supplemental): ${skillsRouted}`);

  const result = runAgentRuntime({
    root,
    reportPath: options.report,
    routedSkillsPath: options.routedSkills,
    outputPath: options.output,
    provider: options.provider,
    model: options.model,
    mode: options.mode ?? "full",
    fromCache: options.fromCache,
  });

  const activation = readActivationSummary(result.outputPath, skillsRouted);

  console.log("Specialist runtime complete.");
  console.log(`Provider: ${result.provider}`);
  console.log(`Model: ${result.model}`);
  if (result.runtimeMetrics?.mode) {
    console.log(`Mode: ${result.runtimeMetrics.mode}`);
  }
  if (result.runtimeMetrics?.elapsedMs != null) {
    console.log(`Elapsed: ${result.runtimeMetrics.elapsedMs} ms`);
  }
  const cache = result.runtimeMetrics?.cache;
  if (cache?.scanHash) {
    console.log(`Cache: ${cache.hit ? "hit" : "miss"}  scanHash=${cache.scanHash}`);
  }
  const calls = result.runtimeMetrics?.providerCalls ?? [];
  if (cache?.hit) {
    console.log("Model calls: 0");
  } else if (calls.length > 0) {
    const totalTokens = calls.reduce((sum, call) => {
      const tokens = call.totalTokens;
      return sum + (typeof tokens === "number" ? tokens : 0);
    }, 0);
    console.log(`Model calls: ${calls.length}${totalTokens ? `  Tokens: ${totalTokens}` : ""}`);
  }
  console.log(`Findings: ${result.outputPath}`);
  console.log(`Report: ${deriveFindingsMarkdownPath(result.outputPath)}`);
  printActivationSummary(activation);
}

export { deriveFindingsOutputPath, runAgentRuntime };
