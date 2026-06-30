import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

export const DEMO_COMMANDS_FILENAME = "latest-demo-commands.txt";

export interface DemoCommandsInput {
  findingsReportPath: string;
  scanReportPath: string;
  bestFindingId: string | null;
  reportsDir: string;
}

export function buildDemoCommandsText(input: DemoCommandsInput): string {
  const reportFlag = ` --report ${input.findingsReportPath}`;
  const lines = [
    "# Cyber Swarm — live demo follow-up commands",
    "# Copy/paste these during judging.",
    "",
    `swarm findings --demo${reportFlag}`,
    `swarm findings --best${reportFlag}`,
  ];

  if (input.bestFindingId) {
    lines.push(`swarm explain ${input.bestFindingId}${reportFlag}`);
    lines.push(`swarm fix ${input.bestFindingId}${reportFlag}`);
  } else {
    lines.push("swarm explain <finding-id>");
    lines.push("swarm fix <finding-id>");
  }

  lines.push(
    "",
    "# Instant replay (no model calls):",
    `swarm demo ${input.scanReportPath.replace(/\\/g, "/")} --from-cache`,
    `swarm agents run --report ${input.scanReportPath} --from-cache --mode demo`,
  );

  return `${lines.join("\n")}\n`;
}

export function writeDemoCommandsFile(input: DemoCommandsInput): string {
  const outputPath = join(input.reportsDir, DEMO_COMMANDS_FILENAME);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, buildDemoCommandsText(input), "utf8");
  return outputPath;
}

export function formatBestFindingOutput(
  findingId: string,
  options: { reportPath?: string } = {},
): string {
  const reportFlag = options.reportPath ? ` --report ${options.reportPath}` : "";
  return [
    "Best demo-ready finding",
    "=".repeat(28),
    "",
    `ID: ${findingId}`,
    "",
    "Next commands:",
    `  swarm explain ${findingId}${reportFlag}`,
    `  swarm fix ${findingId}${reportFlag}`,
    `  swarm findings --demo${reportFlag}`,
  ].join("\n");
}
