import { resolve } from "node:path";

import { loadConfig } from "../config/load";
import { printCliError } from "./errors";
import { runScan, printInventorySummary, printStackSummary, printSurfacesSummary } from "../scanner";

export function runScanCommand(scanPath?: string): void {
  const workspaceRoot = resolve(process.cwd());
  const targetRoot = resolve(scanPath ?? workspaceRoot);
  const config = loadConfig(workspaceRoot);

  const { report, reportPath } = runScan(targetRoot, config, {
    outputRoot: workspaceRoot,
  });

  console.log("Scan complete.");
  if (targetRoot !== workspaceRoot) {
    console.log(`Target: ${targetRoot}`);
    console.log(`Workspace: ${workspaceRoot}`);
  }
  printInventorySummary(report.inventory);
  printStackSummary(report.stack ?? []);
  printSurfacesSummary(report.surfaces ?? { routes: [], api: [], auth: [], dataModels: [] });
  console.log(`Report: ${reportPath}`);
}
