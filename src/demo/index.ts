import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

import { runAgentRuntime } from "../agents/runtime";
import { planAgentsFromScanReport } from "../agents/planner";
import { readActivationSummary, readRoutedSkillsCount } from "../agents/summary";
import { loadConfig } from "../config/load";
import { deriveFindingsMarkdownPath, loadFindingsReport } from "../findings/load";
import { formatFindingsTable } from "../findings/display";
import { filterDemoFindings, findBestDemoFinding } from "../findings/demoQuality";
import { runScan } from "../scanner";
import { findLatestScanReportForTarget } from "../scanner/reports";
import { readScanReport, routeSkillsFromReport } from "../skills/router";
import { writeDemoCommandsFile } from "./commands";
import { DemoError } from "./errors";
import { printMetric, printRuntimeMetrics, printSectionHeader } from "./format";

const PACKAGE_RUNTIME_ROOT = join(__dirname, "..", "..", "agent_runtime");

function resolveRuntimeRoot(workspaceRoot: string): string {
  const local = join(workspaceRoot, "agent_runtime");
  return existsSync(local) ? local : PACKAGE_RUNTIME_ROOT;
}

export interface DemoRunOptions {
  target?: string;
  provider?: "openai" | "mock" | "local";
  model?: string;
  fromCache?: boolean;
  latency?: "fastest" | "balanced" | "thorough";
  noLlm?: boolean;
  forceLlm?: boolean;
}

export interface DemoRunResult {
  workspaceRoot: string;
  targetRoot: string;
  scanReportPath: string;
  findingsReportPath: string;
  routedSkillsPath: string;
  demoCommandsPath: string;
  bestFindingId: string | null;
  cacheHit?: boolean;
}

function summarizeRuntimeMetrics(
  result: Awaited<ReturnType<typeof runAgentRuntime>>,
): Parameters<typeof printRuntimeMetrics>[0] {
  const calls = result.runtimeMetrics?.providerCalls ?? [];
  const totalTokens = calls.reduce((sum, call) => {
    const tokens = call.totalTokens;
    return sum + (typeof tokens === "number" ? tokens : 0);
  }, 0);

  return {
    provider: result.provider,
    model: result.model,
    mode: result.runtimeMetrics?.mode,
    latencyMode: result.runtimeMetrics?.latencyMode,
    elapsedMs: result.runtimeMetrics?.elapsedMs,
    cacheHit: result.runtimeMetrics?.cache?.hit,
    scanHash: result.runtimeMetrics?.cache?.scanHash,
    llmCacheHit: result.runtimeMetrics?.llmCache?.hit,
    inputTokenEstimate: result.runtimeMetrics?.llmCache?.inputTokenEstimate,
    outputTokens: result.runtimeMetrics?.llmCache?.outputTokens,
    modelLatencyMs: result.runtimeMetrics?.llmCache?.modelLatencyMs,
    stageTimings: result.runtimeMetrics?.stageTimings,
    modelCalls: result.runtimeMetrics?.cache?.hit ? 0 : calls.length,
    tokens: totalTokens > 0 ? totalTokens : undefined,
  };
}

export function runDemoCommand(options: DemoRunOptions = {}): DemoRunResult {
  const workspaceRoot = resolve(process.cwd());
  const targetRoot = resolve(options.target ?? workspaceRoot);
  const config = loadConfig(workspaceRoot);

  printSectionHeader("Cyber Swarm live demo");
  printMetric("Target repo", targetRoot);
  printMetric("Workspace", workspaceRoot);

  printSectionHeader(options.fromCache ? "1. Reuse scan (from cache)" : "1. Scan target");
  let scanReportPath: string;
  let scanElapsedMs = 0;
  if (options.fromCache) {
    const cachedScan = findLatestScanReportForTarget(
      resolve(workspaceRoot, config.outputDir),
      targetRoot,
    );
    if (!cachedScan) {
      throw new DemoError(
        `No prior scan for ${targetRoot}. Run \`swarm demo ${formatDemoTargetArg(targetRoot, workspaceRoot)}\` without --from-cache first.`,
      );
    }
    scanReportPath = cachedScan;
    printMetric("Scan report (reused)", scanReportPath);
  } else {
    const scanStarted = Date.now();
    ({ reportPath: scanReportPath } = runScan(targetRoot, config, {
      outputRoot: workspaceRoot,
    }));
    scanElapsedMs = Date.now() - scanStarted;
    printMetric("Scan report", scanReportPath);
    printMetric("Scan elapsed", `${scanElapsedMs} ms`);
  }

  printSectionHeader("2. Route playbooks");
  const routeStarted = Date.now();
  const routed = routeSkillsFromReport(workspaceRoot, config, scanReportPath);
  const routeElapsedMs = Date.now() - routeStarted;
  printMetric("Playbooks routed", routed.output.selected.length);
  for (const skill of routed.output.selected.slice(0, 5)) {
    const reason = skill.reasons[0] ?? "matched repo signals";
    console.log(`    ${skill.name} — ${reason}`);
  }
  if (routed.output.selected.length > 5) {
    console.log(`    … and ${routed.output.selected.length - 5} more`);
  }
  printMetric("Routed cache", routed.outputPath);
  printMetric("Route elapsed", `${routeElapsedMs} ms`);

  const plannedAgents = planAgentsFromScanReport(readScanReport(scanReportPath));

  printSectionHeader("3. Run specialists (demo mode)");
  printMetric("Planned specialists", plannedAgents.length);
  for (const agent of plannedAgents.slice(0, 5)) {
    console.log(`    ${agent.specialist} — ${agent.reasons[0] ?? "surface match"}`);
  }
  if (options.fromCache) {
    printMetric("Replay", "from cache (no model calls)");
  }

  const agentResult = runAgentRuntime({
    root: workspaceRoot,
    reportPath: scanReportPath,
    routedSkillsPath: routed.outputPath,
    provider: options.provider,
    model: options.model,
    mode: "demo",
    fromCache: options.fromCache,
    latency: options.latency,
    noLlm: options.noLlm,
    forceLlm: options.forceLlm,
    runtimeRoot: resolveRuntimeRoot(workspaceRoot),
  });

  printRuntimeMetrics(summarizeRuntimeMetrics(agentResult));
  printMetric("Findings JSON", agentResult.outputPath);
  printMetric("Findings report", deriveFindingsMarkdownPath(agentResult.outputPath));

  const activation = readActivationSummary(
    agentResult.outputPath,
    readRoutedSkillsCount(routed.outputPath),
  );
  printMetric("Verified findings", activation.findingsVerified);
  printMetric("Rejected findings", activation.findingsRejected);

  const findingsReport = loadFindingsReport(agentResult.outputPath);
  const demoFindings = filterDemoFindings(findingsReport.verifiedFindings);
  const bestFinding = findBestDemoFinding(findingsReport.verifiedFindings);

  printSectionHeader("4. Demo-ready findings");
  console.log(formatFindingsTable(findingsReport, agentResult.outputPath, { demoOnly: true }));

  const demoCommandsPath = writeDemoCommandsFile({
    findingsReportPath: agentResult.outputPath,
    scanReportPath,
    targetRoot,
    bestFindingId: bestFinding?.id ?? null,
    reportsDir: resolve(workspaceRoot, config.outputDir),
  });

  printSectionHeader("Next commands");
  console.log(`  swarm findings --demo`);
  console.log(`  swarm findings --best`);
  if (bestFinding) {
    console.log(`  swarm explain ${bestFinding.id}`);
    console.log(`  swarm fix ${bestFinding.id}`);
  }
  console.log(`  swarm demo ${formatDemoTargetArg(targetRoot, workspaceRoot)} --from-cache`);
  printMetric("Command cheat sheet", demoCommandsPath);

  if (demoFindings.length === 0) {
    console.log("");
    console.log("  No demo-ready findings yet — review the full report or adjust the target.");
  }

  return {
    workspaceRoot,
    targetRoot,
    scanReportPath,
    findingsReportPath: agentResult.outputPath,
    routedSkillsPath: routed.outputPath,
    demoCommandsPath,
    bestFindingId: bestFinding?.id ?? null,
    cacheHit: agentResult.runtimeMetrics?.cache?.hit,
  };
}

function formatDemoTargetArg(targetRoot: string, workspaceRoot: string): string {
  if (normalizeRoot(targetRoot) === normalizeRoot(workspaceRoot)) {
    return ".";
  }
  return targetRoot;
}

function normalizeRoot(path: string): string {
  return resolve(path).replace(/\\/g, "/").toLowerCase();
}
