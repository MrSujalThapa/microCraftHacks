import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { deriveFindingsMarkdownPath } from "../findings/load";
import { deriveFindingsOutputPath, runAgentRuntime } from "./runtime";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-agents-"));
  tempRoots.push(root);
  return root;
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("deriveFindingsOutputPath", () => {
  it("derives findings filename from scan report path", () => {
    const output = deriveFindingsOutputPath(
      ".swarm/reports/scan-2026-06-29T12-00-00-000Z.json",
    );
    expect(output.endsWith("scan-2026-06-29T12-00-00-000Z-findings.json")).toBe(true);
    expect(output.includes(".swarm")).toBe(true);
    expect(output.includes("reports")).toBe(true);
  });
});

describe("runAgentRuntime", () => {
  it("invokes Python runtime and writes findings JSON", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: {
            totalFiles: 0,
            byCategory: {},
            files: [],
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const result = runAgentRuntime({
      root,
      reportPath,
      routedSkillsPath,
      runtimeRoot: join(repoRoot, "agent_runtime"),
      provider: "mock",
    });

    expect(existsSync(result.outputPath)).toBe(true);
    const payload = JSON.parse(readFileSync(result.outputPath, "utf8")) as {
      verifiedFindings: unknown[];
      status: string;
    };
    expect(payload.status).toBe("completed");
    expect(payload.verifiedFindings).toEqual([]);

    const markdownPath = deriveFindingsMarkdownPath(result.outputPath);
    expect(existsSync(markdownPath)).toBe(true);
    const markdown = readFileSync(markdownPath, "utf8");
    expect(markdown).toContain("# Cyber Swarm Findings Report");
    expect(markdown).toContain("## Executive summary");
  });

  it("invokes Python runtime in demo mode", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: {
            totalFiles: 0,
            byCategory: {},
            files: [],
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const result = runAgentRuntime({
      root,
      reportPath,
      routedSkillsPath,
      runtimeRoot: join(repoRoot, "agent_runtime"),
      provider: "mock",
      mode: "demo",
    });

    expect(result.runtimeMetrics?.mode).toBe("demo");
    expect(existsSync(result.outputPath)).toBe(true);
  });

  it("invokes Python runtime in fast mode", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: {
            totalFiles: 0,
            byCategory: {},
            files: [],
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const result = runAgentRuntime({
      root,
      reportPath,
      routedSkillsPath,
      runtimeRoot: join(repoRoot, "agent_runtime"),
      provider: "mock",
      mode: "fast",
    });

    expect(result.runtimeMetrics?.mode).toBe("fast");
    expect(existsSync(result.outputPath)).toBe(true);
  });

  it("surfaces Python stderr when runtime fails", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: { totalFiles: 0, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    expect(() =>
      runAgentRuntime({
        root,
        reportPath,
        routedSkillsPath,
        runtimeRoot: join(root, "missing-runtime"),
        provider: "mock",
        mode: "demo",
      }),
    ).toThrow(/Python runtime root not found/);
  });

  it("from-cache fails fast when no cached run exists", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: { totalFiles: 0, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    expect(() =>
      runAgentRuntime({
        root,
        reportPath,
        routedSkillsPath,
        runtimeRoot: join(repoRoot, "agent_runtime"),
        provider: "mock",
        fromCache: true,
      }),
    ).toThrow(/No cached agent run for this scan hash/);
  });

  it("from-cache replays cached findings without model calls", () => {
    const repoRoot = resolveRepoRoot();
    const root = makeTempRoot();
    const reportPath = join(root, "scan-test.json");
    const routedSkillsPath = join(root, "routed-skills.json");

    writeFileSync(
      reportPath,
      `${JSON.stringify(
        {
          version: "0.1.0",
          scannedAt: "2026-06-29T12:00:00.000Z",
          projectRoot: root,
          inventory: { totalFiles: 0, byCategory: {}, files: [] },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    writeFileSync(
      routedSkillsPath,
      `${JSON.stringify(
        {
          reportPath,
          routedAt: "2026-06-29T12:01:00.000Z",
          selected: [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const first = runAgentRuntime({
      root,
      reportPath,
      routedSkillsPath,
      runtimeRoot: join(repoRoot, "agent_runtime"),
      provider: "mock",
      mode: "full",
    });
    expect(first.runtimeMetrics?.cache?.hit).toBe(false);

    const replay = runAgentRuntime({
      root,
      reportPath,
      routedSkillsPath,
      runtimeRoot: join(repoRoot, "agent_runtime"),
      provider: "mock",
      mode: "full",
      fromCache: true,
    });

    expect(replay.runtimeMetrics?.cache?.hit).toBe(true);
    expect(replay.runtimeMetrics?.providerCalls ?? []).toHaveLength(0);
    expect(replay.runtimeMetrics?.elapsedMs ?? Number.MAX_SAFE_INTEGER).toBeLessThan(5000);
  });
});

function resolveRepoRoot(): string {
  return join(__dirname, "..", "..");
}
