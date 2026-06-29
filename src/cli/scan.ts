import { resolve } from "node:path";

import { loadConfig } from "../config/load";
import { printCliError } from "./errors";
import { runScan, printInventorySummary, printStackSummary, printSurfacesSummary } from "../scanner";

export function runScanCommand(scanPath?: string): void {
  const root = resolve(scanPath ?? process.cwd());
  const config = loadConfig(root);

  const { report, reportPath } = runScan(root, config);

  console.log("Scan complete.");
  printInventorySummary(report.inventory);
  printStackSummary(report.stack ?? []);
  printSurfacesSummary(report.surfaces ?? { routes: [], api: [], auth: [], dataModels: [] });
  console.log(`Report: ${reportPath}`);
}
