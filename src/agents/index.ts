import { resolve } from "node:path";

import { deriveFindingsMarkdownPath } from "../findings/load";
import { deriveFindingsOutputPath, runAgentRuntime } from "./runtime";

export function runAgentsCommand(options: {
  report: string;
  routedSkills?: string;
  output?: string;
  provider?: "openai" | "mock" | "local";
  model?: string;
}): void {
  const root = resolve(process.cwd());
  const result = runAgentRuntime({
    root,
    reportPath: options.report,
    routedSkillsPath: options.routedSkills,
    outputPath: options.output,
    provider: options.provider,
    model: options.model,
  });

  console.log("Agent runtime complete.");
  console.log(`Provider: ${result.provider}`);
  console.log(`Model: ${result.model}`);
  if (result.runtimeMetrics?.elapsedMs != null) {
    console.log(`Elapsed: ${result.runtimeMetrics.elapsedMs} ms`);
  }
  const calls = result.runtimeMetrics?.providerCalls ?? [];
  if (calls.length > 0) {
    const totalTokens = calls.reduce((sum, call) => {
      const tokens = call.totalTokens;
      return sum + (typeof tokens === "number" ? tokens : 0);
    }, 0);
    console.log(`Model calls: ${calls.length}${totalTokens ? `  Tokens: ${totalTokens}` : ""}`);
  }
  console.log(`Findings: ${result.outputPath}`);
  console.log(`Report: ${deriveFindingsMarkdownPath(result.outputPath)}`);
}

export { deriveFindingsOutputPath, runAgentRuntime };
