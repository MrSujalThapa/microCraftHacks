import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { findLatestScanReportForTarget } from "./reports";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-scan-reports-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("findLatestScanReportForTarget", () => {
  it("returns the newest scan report for a matching project root", () => {
    const root = makeTempRoot();
    const target = join(root, "wattif");
    const reportsDir = join(root, ".swarm", "reports");
    mkdirSync(reportsDir, { recursive: true });

    writeFileSync(
      join(reportsDir, "scan-2026-06-29T12-00-00-000Z.json"),
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: target,
          inventory: { totalFiles: 1, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    writeFileSync(
      join(reportsDir, "scan-2026-06-30T00-00-00-000Z.json"),
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-30T00:00:00.000Z",
          projectRoot: target,
          inventory: { totalFiles: 2, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    utimesSync(
      join(reportsDir, "scan-2026-06-29T12-00-00-000Z.json"),
      new Date("2026-06-29T12:00:00.000Z"),
      new Date("2026-06-29T12:00:00.000Z"),
    );
    utimesSync(
      join(reportsDir, "scan-2026-06-30T00-00-00-000Z.json"),
      new Date("2026-06-30T00:00:00.000Z"),
      new Date("2026-06-30T00:00:00.000Z"),
    );

    const latest = findLatestScanReportForTarget(reportsDir, target);
    expect(latest?.endsWith("scan-2026-06-30T00-00-00-000Z.json")).toBe(true);
  });

  it("ignores scan reports for other targets", () => {
    const root = makeTempRoot();
    const target = join(root, "wattif");
    const other = join(root, "other");
    const reportsDir = join(root, ".swarm", "reports");
    mkdirSync(reportsDir, { recursive: true });

    writeFileSync(
      join(reportsDir, "scan-2026-06-30T00-00-00-000Z.json"),
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-30T00:00:00.000Z",
          projectRoot: other,
          inventory: { totalFiles: 1, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    expect(findLatestScanReportForTarget(reportsDir, target)).toBeNull();
  });
});
