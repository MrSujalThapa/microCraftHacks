import { resolve } from "node:path";

import { loadConfig } from "../config/load";
import {
  findVerifiedFinding,
  loadFindingsReport,
  resolveFindingsReportPath,
} from "./load";
import { formatFindingExplanation, formatFindingsTable } from "./display";

export function runFindingsCommand(options: { report?: string } = {}): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);
  const reportPath = resolveFindingsReportPath(config.outputDir, options.report);
  const report = loadFindingsReport(reportPath);

  console.log(formatFindingsTable(report, reportPath));
}

export function runExplainCommand(findingId: string, options: { report?: string } = {}): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);
  const reportPath = resolveFindingsReportPath(config.outputDir, options.report);
  const report = loadFindingsReport(reportPath);
  const finding = findVerifiedFinding(report, findingId);

  console.log(formatFindingExplanation(finding));
}

export {
  deriveFindingsMarkdownPath,
  findLatestFindingsReport,
  findVerifiedFinding,
  loadFindingsReport,
  resolveFindingsReportPath,
} from "./load";
export { formatFindingExplanation, formatFindingsTable } from "./display";
export { FindingsError } from "./errors";
export type { FindingsReport, VerifiedFinding } from "./types";
