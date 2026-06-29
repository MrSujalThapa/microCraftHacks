import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import type { ScanReport } from "../scanner/types";
import { buildSkillsIndex } from "./indexer";
import { routeSkills, routeSkillsFromReport } from "./router";
import type { SkillIndexEntry } from "./types";

const tempRoots: string[] = [];

function makeTempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "cyber-swarm-skills-route-"));
  tempRoots.push(root);
  return root;
}

function writeSkill(root: string, relativeDir: string, name: string, tags: string[]): void {
  const dir = join(root, relativeDir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "SKILL.md"),
    `---
name: ${name}
description: Skill for ${tags.join(" ")}
tags: [${tags.map((t) => `"${t}"`).join(", ")}]
---
Full body for ${name}
`,
    "utf8",
  );
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("routeSkills", () => {
  it("selects skills matching stack and auth surfaces before loading bodies", () => {
    const skills: SkillIndexEntry[] = [
      {
        name: "detecting-broken-access-control",
        description: "Authorization and IDOR checks",
        subdomain: "web-application-security",
        tags: ["auth", "authorization", "idor"],
        path: "skills/external/auth/SKILL.md",
        sourceType: "external",
      },
      {
        name: "scanning-for-secrets",
        description: "Find leaked secrets in repos",
        tags: ["secrets", "credential"],
        path: "skills/external/secrets/SKILL.md",
        sourceType: "external",
      },
      {
        name: "unrelated-skill",
        description: "Nothing relevant here",
        tags: ["mobile"],
        path: "skills/external/mobile/SKILL.md",
        sourceType: "external",
      },
    ];

    const report: ScanReport = {
      version: "0.1.0",
      scannedAt: "2026-06-29T00:00:00.000Z",
      projectRoot: "/tmp/project",
      inventory: {
        totalFiles: 2,
        byCategory: { typescript: 2 },
        files: [
          { path: "src/middleware.ts", category: "typescript" },
          { path: "src/auth/session.ts", category: "typescript" },
        ],
      },
      stack: [{ name: "Express", confidence: "high", evidence: ["package.json"] }],
      surfaces: {
        routes: [{ path: "/dashboard", file: "src/routes/dashboard.ts", framework: "express" }],
        api: [{ path: "/api/users", file: "src/routes/users.ts", framework: "express" }],
        auth: [{ file: "src/middleware.ts", type: "middleware" }],
        dataModels: [],
      },
    };

    const selected = routeSkills(report, { skills });

    expect(selected.map((s) => s.name)).toContain("detecting-broken-access-control");
    expect(selected.map((s) => s.name)).not.toContain("unrelated-skill");
    expect(selected[0].reasons.length).toBeGreaterThan(0);
    expect(selected[0].agentTypes).toContain("auth");
  });
});

describe("routeSkillsFromReport", () => {
  it("writes routed cache and loads bodies only for selected skills", () => {
    const root = makeTempRoot();
    const config = createDefaultConfig(root);

    writeSkill(
      root,
      "skills/external/Anthropic-Cybersecurity-Skills/skills/auth",
      "auth-check",
      ["auth", "api"],
    );
    writeSkill(
      root,
      "skills/external/Anthropic-Cybersecurity-Skills/skills/other",
      "other-skill",
      ["mobile"],
    );

    buildSkillsIndex(root, config);

    const reportPath = join(root, ".swarm/reports/scan-test.json");
    mkdirSync(join(root, ".swarm/reports"), { recursive: true });
    const report: ScanReport = {
      version: "0.1.0",
      scannedAt: "2026-06-29T00:00:00.000Z",
      projectRoot: root,
      inventory: {
        totalFiles: 1,
        byCategory: { typescript: 1 },
        files: [{ path: "src/auth.ts", category: "typescript" }],
      },
      stack: [{ name: "Express", confidence: "high", evidence: ["package.json"] }],
      surfaces: {
        routes: [],
        api: [{ path: "/api/login", file: "src/api.ts", framework: "express" }],
        auth: [{ file: "src/auth.ts", type: "middleware" }],
        dataModels: [],
      },
    };
    writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

    const result = routeSkillsFromReport(root, config, reportPath);

    expect(result.output.selected.some((s) => s.name === "auth-check")).toBe(true);
    expect(result.output.loaded.length).toBe(result.output.selected.length);
    expect(result.output.loaded[0].body).toContain("Full body");

    const raw = readFileSync(result.outputPath, "utf8");
    expect(raw).not.toContain("other-skill");
    expect(existsSync(result.outputPath)).toBe(true);
  });
});
