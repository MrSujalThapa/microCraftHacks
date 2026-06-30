import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { FindingsError } from "./errors";
import { sampleFindingsReport } from "./fixtures";
import {
  findLatestFindingsReport,
  findVerifiedFinding,
  loadFindingsReport,
  resolveFindingsReportPath,
} from "./load";

const tempRoots: string[] = [];

function writeReport(path: string, payload: unknown = {}): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-findings-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("resolveFindingsReportPath", () => {
  it("throws when no reports exist", () => {
    const root = makeTempRoot();
    const reportsDir = join(root, ".swarm", "reports");

    expect(() => resolveFindingsReportPath(reportsDir)).toThrow(FindingsError);
    expect(() => resolveFindingsReportPath(reportsDir)).toThrow(/No findings reports/);
  });

  it("returns latest findings report by mtime", () => {
    const root = makeTempRoot();
    const reportsDir = join(root, ".swarm", "reports");
    const older = join(reportsDir, "scan-old-findings.json");
    const newer = join(reportsDir, "scan-new-findings.json");

    writeReport(older, {});
    writeReport(newer, {});

    const resolved = resolveFindingsReportPath(reportsDir);
    expect(resolved).toBe(newer);
  });

  it("uses explicit report path when provided", () => {
    const root = makeTempRoot();
    const reportPath = join(root, "custom-findings.json");
    writeReport(reportPath, {});

    expect(resolveFindingsReportPath(join(root, ".swarm", "reports"), reportPath)).toBe(
      reportPath,
    );
  });
});

describe("loadFindingsReport", () => {
  it("loads verified findings from JSON", () => {
    const root = makeTempRoot();
    const reportPath = join(root, "findings.json");
    writeReport(reportPath, sampleFindingsReport());

    const report = loadFindingsReport(reportPath);
    expect(report.verifiedFindings).toHaveLength(1);
    expect(report.verifiedFindings[0]?.id).toBe("verified-draft-auth-1");
  });
});

describe("findVerifiedFinding", () => {
  it("returns verified finding by id", () => {
    const report = sampleFindingsReport();
    const finding = findVerifiedFinding(report, "verified-draft-auth-1");
    expect(finding.title).toContain("Missing auth guard");
  });

  it("rejects rejected finding ids with clear error", () => {
    const report = sampleFindingsReport();
    expect(() => findVerifiedFinding(report, "draft-unsupported")).toThrow(/rejected/i);
  });

  it("errors for unknown ids", () => {
    const report = sampleFindingsReport();
    expect(() => findVerifiedFinding(report, "missing-id")).toThrow(FindingsError);
  });
});

describe("findLatestFindingsReport", () => {
  it("returns null when reports directory is missing", () => {
    expect(findLatestFindingsReport(join(makeTempRoot(), "missing"))).toBeNull();
  });

  it("ignores non-findings json files", () => {
    const root = makeTempRoot();
    const reportsDir = join(root, ".swarm", "reports");
    writeReport(join(reportsDir, "scan-only.json"), {});
    expect(findLatestFindingsReport(reportsDir)).toBeNull();
    expect(existsSync(join(reportsDir, "scan-only.json"))).toBe(true);
  });
});
