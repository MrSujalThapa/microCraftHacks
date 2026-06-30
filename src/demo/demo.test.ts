import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import { getConfigPath } from "../config/paths";
import { getSkillsIndexPath } from "../skills/paths";
import { runAgentRuntime } from "../agents/runtime";
import { buildDemoCommandsText, writeDemoCommandsFile } from "./commands";
import { runDemoCommand } from "./index";
import { findBestDemoFinding } from "../findings/demoQuality";
import { sampleFindingsReport } from "../findings/fixtures";
import type { VerifiedFinding } from "../findings/types";
import { formatFixPlan } from "../findings/fix";
import { containsRawSecret } from "../shared/redaction";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-demo-"));
  tempRoots.push(root);
  return root;
}

function writeWorkspace(root: string): void {
  mkdirSync(join(root, ".swarm"), { recursive: true });
  writeFileSync(getConfigPath(root), `${JSON.stringify(createDefaultConfig(root), null, 2)}\n`, "utf8");
  const config = createDefaultConfig(root);
  mkdirSync(join(root, config.cacheDir), { recursive: true });
  mkdirSync(join(root, config.outputDir), { recursive: true });
  writeFileSync(
    getSkillsIndexPath(root, config),
    `${JSON.stringify({ version: 1, count: 0, skills: [], builtAt: new Date().toISOString() }, null, 2)}\n`,
    "utf8",
  );
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("buildDemoCommandsText", () => {
  it("includes follow-up commands with finding id", () => {
    const text = buildDemoCommandsText({
      findingsReportPath: ".swarm/reports/scan-findings.json",
      scanReportPath: ".swarm/reports/scan.json",
      bestFindingId: "verified-secret-1",
      reportsDir: ".swarm/reports",
    });

    expect(text).toContain("swarm findings --demo");
    expect(text).toContain("swarm findings --best");
    expect(text).toContain("swarm explain verified-secret-1");
    expect(text).toContain("swarm fix verified-secret-1");
    expect(text).toContain("--from-cache");
  });
});

describe("findBestDemoFinding", () => {
  it("returns the secret finding for wattif-shaped reports", () => {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    const secretFinding: VerifiedFinding = {
      ...base,
      id: "verified-draft-h1",
      title: "Hardcoded SUPABASE_SERVICE_ROLE_KEY in backend/.env",
      vulnerability_class: "secret-exposure",
      claim: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          path: "backend/.env",
          line_start: 4,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
        },
      ],
      demo_ready: true,
    };
    const noiseFinding: VerifiedFinding = {
      ...base,
      id: "verified-health",
      title: "/api/health handler lacks visible auth dependency",
      demo_ready: false,
    };

    const best = findBestDemoFinding([noiseFinding, secretFinding]);
    expect(best?.id).toBe("verified-draft-h1");
  });
});

describe("formatFixPlan secret remediation", () => {
  it("does not treat REDACTED_SECRET as a credential key name", () => {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    const secretFinding: VerifiedFinding = {
      ...base,
      id: "verified-secret-1",
      title: "Committed secret in backend/.env",
      vulnerability_class: "secret-exposure",
      claim: "backend/.env exposed SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          path: "backend/.env",
          line_start: 1,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
          symbol: "SUPABASE_SERVICE_ROLE_KEY",
        },
      ],
      safe_reproduction: {
        mode: "static-proof",
        steps: ["Open backend/.env"],
        expected_result: "Secret line present.",
        safety_notes: [],
      },
    };

    const output = formatFixPlan(secretFinding, "report.json");
    expect(output).toContain("Rotate the exposed SUPABASE_SERVICE_ROLE_KEY");
    expect(output).not.toMatch(/Rotate the exposed REDACTED_SECRET/i);
    expect(output).not.toMatch(/Rotate REDACTED_SECRET/i);
  });
});

describe("runDemoCommand", () => {
  it("runs scan, route, and demo specialists with mock provider", () => {
    const root = makeTempRoot();
    writeWorkspace(root);
    mkdirSync(join(root, "backend"), { recursive: true });
    writeFileSync(join(root, "backend", "main.py"), "print('demo')\n", "utf8");

    const previousCwd = process.cwd();
    process.chdir(root);
    try {
      const result = runDemoCommand({ provider: "mock" });

      expect(existsSync(result.scanReportPath)).toBe(true);
      expect(existsSync(result.findingsReportPath)).toBe(true);
      expect(existsSync(result.demoCommandsPath)).toBe(true);
      expect(readFileSync(result.demoCommandsPath, "utf8")).toContain("swarm findings --demo");
    } finally {
      process.chdir(previousCwd);
    }
  });

  it("from-cache demo replay does not call the model", () => {
    const repoRoot = join(__dirname, "..", "..");
    const root = makeTempRoot();
    writeWorkspace(root);

    const previousCwd = process.cwd();
    process.chdir(root);
    try {
      runDemoCommand({ provider: "mock" });

      const replay = runAgentRuntime({
        root,
        reportPath: join(root, ".swarm", "reports", readLatestScanReport(root)),
        routedSkillsPath: join(root, ".swarm", "cache", "routed-skills.json"),
        runtimeRoot: join(repoRoot, "agent_runtime"),
        provider: "mock",
        mode: "demo",
        fromCache: true,
      });

      expect(replay.runtimeMetrics?.cache?.hit).toBe(true);
      expect(replay.runtimeMetrics?.providerCalls ?? []).toHaveLength(0);
    } finally {
      process.chdir(previousCwd);
    }
  });
});

describe("writeDemoCommandsFile", () => {
  it("writes latest-demo-commands.txt under reports dir", () => {
    const root = makeTempRoot();
    const reportsDir = join(root, ".swarm", "reports");
    mkdirSync(reportsDir, { recursive: true });

    const path = writeDemoCommandsFile({
      findingsReportPath: join(reportsDir, "scan-findings.json"),
      scanReportPath: join(reportsDir, "scan.json"),
      bestFindingId: "verified-draft-h1",
      reportsDir,
    });

    expect(path.endsWith("latest-demo-commands.txt")).toBe(true);
    expect(readFileSync(path, "utf8")).toContain("swarm agents run");
    expect(containsRawSecret(readFileSync(path, "utf8"))).toBe(false);
  });
});

function readLatestScanReport(root: string): string {
  const reportsDir = join(root, ".swarm", "reports");
  const files = readdirSync(reportsDir).filter(
    (name) => name.startsWith("scan-") && name.endsWith(".json") && !name.includes("-findings"),
  );
  files.sort();
  return files.at(-1)!;
}
