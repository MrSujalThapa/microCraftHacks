import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { FindingsError } from "./errors";
import type { FindingsReport, VerifiedFinding } from "./types";

const FINDINGS_SUFFIX = "-findings.json";

export function deriveFindingsMarkdownPath(findingsJsonPath: string): string {
  return findingsJsonPath.replace(/\.json$/i, ".md");
}

export function resolveFindingsReportPath(
  reportsDir: string,
  reportPath?: string,
): string {
  if (reportPath) {
    const resolved = resolve(reportPath);
    if (!existsSync(resolved)) {
      throw new FindingsError(`Findings report not found: ${resolved}`, "MISSING");
    }
    return resolved;
  }

  const latest = findLatestFindingsReport(reportsDir);
  if (!latest) {
    throw new FindingsError(
      `No findings reports in ${reportsDir}. Run \`swarm agents run --report <scan>\` first.`,
      "MISSING",
    );
  }
  return latest;
}

export function findLatestFindingsReport(reportsDir: string): string | null {
  if (!existsSync(reportsDir)) {
    return null;
  }

  const candidates = readdirSync(reportsDir)
    .filter((name) => name.endsWith(FINDINGS_SUFFIX))
    .map((name) => join(reportsDir, name))
    .filter((path) => existsSync(path));

  if (candidates.length === 0) {
    return null;
  }

  candidates.sort((left, right) => statSync(right).mtimeMs - statSync(left).mtimeMs);
  return candidates[0] ?? null;
}

export function loadFindingsReport(reportPath: string): FindingsReport {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(reportPath, "utf8")) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid JSON";
    throw new FindingsError(
      `Findings report at ${reportPath} is not valid JSON: ${detail}`,
      "INVALID",
    );
  }

  if (!raw || typeof raw !== "object") {
    throw new FindingsError(`Findings report at ${reportPath} is not a JSON object`, "INVALID");
  }

  const report = raw as FindingsReport;
  if (!Array.isArray(report.verifiedFindings)) {
    throw new FindingsError(
      `Findings report at ${reportPath} is missing verifiedFindings array`,
      "INVALID",
    );
  }

  return report;
}

export function findVerifiedFinding(
  report: FindingsReport,
  findingId: string,
): VerifiedFinding {
  const finding = report.verifiedFindings.find((item) => item.id === findingId);
  if (finding) {
    return finding;
  }

  const rejected = report.rejectedFindings.find(
    (item) => item.draft_id === findingId || item.title === findingId,
  );
  if (rejected) {
    throw new FindingsError(
      `Finding "${findingId}" was rejected and cannot be explained or fixed: ${rejected.reason}`,
      "NOT_FOUND",
    );
  }

  throw new FindingsError(
    `Verified finding not found: ${findingId}. Run \`swarm findings\` to list available IDs.`,
    "NOT_FOUND",
  );
}
