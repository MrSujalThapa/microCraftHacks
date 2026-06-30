import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import type { ScanReport } from "./types";

const SCAN_REPORT_PREFIX = "scan-";
const SCAN_REPORT_SUFFIX = ".json";

function normalizeRoot(path: string): string {
  return resolve(path).replace(/\\/g, "/").toLowerCase();
}

function isScanReportFile(name: string): boolean {
  return (
    name.startsWith(SCAN_REPORT_PREFIX) &&
    name.endsWith(SCAN_REPORT_SUFFIX) &&
    !name.includes("-findings")
  );
}

export function findLatestScanReportForTarget(
  reportsDir: string,
  targetRoot: string,
): string | null {
  if (!existsSync(reportsDir)) {
    return null;
  }

  const normalizedTarget = normalizeRoot(targetRoot);
  const candidates: Array<{ path: string; mtimeMs: number }> = [];

  for (const name of readdirSync(reportsDir)) {
    if (!isScanReportFile(name)) {
      continue;
    }
    const reportPath = join(reportsDir, name);
    if (!existsSync(reportPath)) {
      continue;
    }

    let report: ScanReport;
    try {
      report = JSON.parse(readFileSync(reportPath, "utf8")) as ScanReport;
    } catch {
      continue;
    }

    if (normalizeRoot(report.projectRoot) !== normalizedTarget) {
      continue;
    }

    candidates.push({ path: reportPath, mtimeMs: statSync(reportPath).mtimeMs });
  }

  if (candidates.length === 0) {
    return null;
  }

  candidates.sort((left, right) => right.mtimeMs - left.mtimeMs);
  return candidates[0]?.path ?? null;
}
