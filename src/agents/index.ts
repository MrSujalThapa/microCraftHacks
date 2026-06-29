import { resolve } from "node:path";

import { deriveFindingsOutputPath, runAgentRuntime } from "./runtime";

export function runAgentsCommand(options: {
  report: string;
  routedSkills?: string;
  output?: string;
}): void {
  const root = resolve(process.cwd());
  const result = runAgentRuntime({
    root,
    reportPath: options.report,
    routedSkillsPath: options.routedSkills,
    outputPath: options.output,
  });

  console.log("Agent runtime complete.");
  console.log(`Findings: ${result.outputPath}`);
}

export { deriveFindingsOutputPath, runAgentRuntime };
