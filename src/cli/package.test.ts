import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  findMissingPackPaths,
  findPackViolations,
  parsePackLines,
  runPackDryRun,
} from "../../scripts/pack-utils.mjs";

const repoRoot = join(__dirname, "..", "..");
const cliPath = join(repoRoot, "dist/cli/index.js");

describe("CLI package", () => {
  it("built CLI responds to --help", () => {
    const result = spawnSync(process.execPath, [cliPath, "--help"], {
      cwd: repoRoot,
      encoding: "utf8",
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("swarm");
    expect(result.stdout).toContain("doctor");
    expect(result.stdout).toContain("demo");
  });

  it("built CLI entry has executable shebang", () => {
    const firstLine = readFileSync(cliPath, "utf8").split(/\r?\n/u)[0];
    expect(firstLine).toBe("#!/usr/bin/env node");
  });

  it("npm pack --dry-run succeeds via pack:check", () => {
    const packedPaths = parsePackLines(runPackDryRun(repoRoot));
    expect(findPackViolations(packedPaths)).toEqual([]);
    expect(findMissingPackPaths(packedPaths)).toEqual([]);
  }, 30_000);

  it("package excludes reports, cache, env, and external skills", () => {
    const packedPaths = parsePackLines(runPackDryRun(repoRoot));

    expect(packedPaths.some((path) => path.endsWith(".env"))).toBe(false);
    expect(packedPaths.some((path) => path.includes(".swarm/cache"))).toBe(false);
    expect(packedPaths.some((path) => path.includes(".swarm/reports"))).toBe(false);
    expect(packedPaths.some((path) => path.includes("skills/external"))).toBe(false);
    expect(packedPaths.some((path) => path.includes("docs/"))).toBe(false);
    expect(packedPaths.some((path) => path.endsWith(".test.js"))).toBe(false);
    expect(packedPaths.some((path) => path.includes("agent_runtime/tests/"))).toBe(false);
    expect(packedPaths.some((path) => path.includes("__pycache__"))).toBe(false);
  }, 30_000);

  it("package includes runtime and CLI artifacts", () => {
    const packedPaths = parsePackLines(runPackDryRun(repoRoot));

    expect(packedPaths).toContain("dist/cli/index.js");
    expect(packedPaths).toContain("agent_runtime/pyproject.toml");
    expect(packedPaths.some((path) => path.startsWith("agent_runtime/cyber_swarm/"))).toBe(true);
    expect(packedPaths).toContain("README.md");
    expect(packedPaths).toContain("LICENSE");
    expect(packedPaths).toContain(".env.example");
  }, 30_000);
});
