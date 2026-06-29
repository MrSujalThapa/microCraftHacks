import { resolve } from "node:path";

import type { SwarmConfig } from "../config/types";
import { writeScanReport } from "../report/write";
import { getPackageVersion } from "../shared/version";
import { walkRepo } from "./inventory";
import { detectStack, printStackSummary } from "./stack";
import { mapSurfaces, printSurfacesSummary } from "./surfaces";
import type { ScanReport, ScanResult } from "./types";

export { printStackSummary, printSurfacesSummary };

export function printInventorySummary(inventory: ScanReport["inventory"]): void {
  console.log(`Files: ${inventory.totalFiles}`);

  const categories = Object.entries(inventory.byCategory).sort((a, b) => b[1] - a[1]);
  if (categories.length > 0) {
    console.log("Categories:");
    for (const [category, count] of categories) {
      console.log(`  ${category}: ${count}`);
    }
  }

  const relevant = inventory.files.filter((f) =>
    ["typescript", "javascript", "python", "java", "config", "json", "yaml", "docker"].includes(
      f.category,
    ),
  );

  console.log("Source & config files:");
  for (const file of relevant) {
    console.log(`  ${file.path} (${file.category})`);
  }
}

export interface RunScanOptions {
  /** Where to write `.swarm/reports` (defaults to scanned target root). */
  outputRoot?: string;
}

export function runScan(root: string, config: SwarmConfig, options: RunScanOptions = {}): ScanResult {
  const projectRoot = resolve(root);
  const outputRoot = resolve(options.outputRoot ?? projectRoot);
  const scannedAt = new Date().toISOString();
  const inventory = walkRepo(projectRoot);
  const stack = detectStack(projectRoot, inventory);
  const surfaces = mapSurfaces(projectRoot, inventory);

  const report: ScanReport = {
    version: getPackageVersion(),
    scannedAt,
    projectRoot,
    inventory,
    stack,
    surfaces,
  };

  const reportPath = writeScanReport(outputRoot, report, config.outputDir);

  return { report, reportPath };
}
