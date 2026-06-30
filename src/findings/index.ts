import { resolve } from "node:path";

import { loadConfig } from "../config/load";
import {
  findExplainableFinding,
  findVerifiedFinding,
  loadFindingsReport,
  resolveFindingsReportPath,
} from "./load";
import { formatBestFindingOutput } from "../demo/commands";
import { findBestDemoFinding } from "./demoQuality";
import { formatFindingExplanation, formatFindingsTable, formatRejectedExplanation } from "./display";
import { formatFixPlan } from "./fix";

export function runFindingsCommand(
  options: { report?: string; demo?: boolean; best?: boolean } = {},
): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);
  const reportPath = resolveFindingsReportPath(config.outputDir, options.report);
  const report = loadFindingsReport(reportPath);

  if (options.best) {
    const best = findBestDemoFinding(report.verifiedFindings);
    if (!best) {
      console.log("No demo-ready findings. Run `swarm demo <target>` or `swarm findings --demo`.");
      return;
    }
    console.log(formatBestFindingOutput(best.id, { reportPath }));
    return;
  }

  console.log(formatFindingsTable(report, reportPath, { demoOnly: options.demo }));
}

export function runExplainCommand(findingId: string, options: { report?: string } = {}): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);
  const reportPath = resolveFindingsReportPath(config.outputDir, options.report);
  const report = loadFindingsReport(reportPath);
  const explainable = findExplainableFinding(report, findingId);

  if (explainable.kind === "verified") {
    console.log(formatFindingExplanation(explainable.finding, report.evidencePacks));
    return;
  }

  console.log(formatRejectedExplanation(explainable.finding, report.evidencePacks));
}

export function runFixCommand(findingId: string, options: { report?: string } = {}): void {
  const root = resolve(process.cwd());
  const config = loadConfig(root);
  const reportPath = resolveFindingsReportPath(config.outputDir, options.report);
  const report = loadFindingsReport(reportPath);
  const finding = findVerifiedFinding(report, findingId);

  console.log(formatFixPlan(finding, reportPath, report.evidencePacks));
}

export {
  deriveFindingsMarkdownPath,
  findExplainableFinding,
  findLatestFindingsReport,
  findVerifiedFinding,
  loadFindingsReport,
  resolveFindingsReportPath,
} from "./load";
export { formatFindingExplanation, formatFindingsTable, formatRejectedExplanation } from "./display";
export { formatFixPlan } from "./fix";
export { FindingsError } from "./errors";
export type { FindingsReport, VerifiedFinding } from "./types";
