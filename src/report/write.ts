import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { ScanReport } from "../scanner/types";

export function formatReportFilename(scannedAt: string): string {
  const safe = scannedAt.replace(/[:.]/g, "-");
  return `scan-${safe}.json`;
}

export function writeScanReport(
  root: string,
  report: ScanReport,
  outputDir: string,
): string {
  const dir = join(root, outputDir);
  mkdirSync(dir, { recursive: true });

  const filename = formatReportFilename(report.scannedAt);
  const reportPath = join(dir, filename);
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  return reportPath;
}
