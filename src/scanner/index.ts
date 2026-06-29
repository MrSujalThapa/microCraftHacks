import { resolve } from "node:path";

import type { SwarmConfig } from "../config/types";
import { writeScanReport } from "../report/write";
import { getPackageVersion } from "../shared/version";
import { walkRepo } from "./inventory";
import type { ScanReport, ScanResult } from "./types";

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

export function runScan(root: string, config: SwarmConfig): ScanResult {
  const projectRoot = resolve(root);
  const scannedAt = new Date().toISOString();
  const inventory = walkRepo(projectRoot);

  const report: ScanReport = {
    version: getPackageVersion(),
    scannedAt,
    projectRoot,
    inventory,
  };

  const reportPath = writeScanReport(projectRoot, report, config.outputDir);

  return { report, reportPath };
}
