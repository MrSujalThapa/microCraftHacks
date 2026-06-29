import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import type { ScanReport } from "../scanner/types";
import { buildSkillsIndex } from "./indexer";
import { collectRepoEvidence, routeSkills, routeSkillsFromReport, scoreSkill } from "./router";
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

function tsCliReport(root: string): ScanReport {
  return {
    version: "0.1.0",
    scannedAt: "2026-06-29T00:00:00.000Z",
    projectRoot: root,
    inventory: {
      totalFiles: 6,
      byCategory: { typescript: 4, config: 2 },
      files: [
        { path: "src/cli/index.ts", category: "typescript" },
        { path: "src/config/auth.ts", category: "typescript" },
        { path: "src/skills/router.ts", category: "typescript" },
        { path: "package.json", category: "config" },
        { path: "tsconfig.json", category: "config" },
        { path: ".env", category: "config" },
      ],
    },
    stack: [{ name: "TypeScript", confidence: "high", evidence: ["package.json", "tsconfig.json"] }],
    surfaces: {
      routes: [{ path: "/health", file: "src/cli/index.ts", framework: "express" }],
      api: [
        { path: "/api/login", file: "src/config/auth.ts", framework: "express" },
        { path: "/api/orders", file: "src/api/orders.ts", framework: "express" },
      ],
      auth: [{ file: "src/config/auth.ts", type: "middleware" }],
      dataModels: [],
    },
  };
}

function irrelevantSkills(): SkillIndexEntry[] {
  return [
    {
      name: "post-exploiting-microsoft-graph-with-graphrunner",
      description: "Microsoft Graph post exploitation",
      tags: ["graph", "microsoft-graph", "oauth"],
      path: "skills/external/graph/SKILL.md",
      sourceType: "external",
    },
    {
      name: "auditing-kubernetes-rbac-privilege-escalation",
      description: "Kubernetes RBAC escalation review",
      tags: ["kubernetes", "rbac", "cloud"],
      path: "skills/external/k8s/SKILL.md",
      sourceType: "external",
    },
    {
      name: "auditing-uefi-firmware-with-chipsec",
      description: "UEFI firmware audit",
      tags: ["firmware", "uefi", "chipsec"],
      path: "skills/external/firmware/SKILL.md",
      sourceType: "external",
    },
    {
      name: "building-phishing-reporting-button-workflow",
      description: "Phishing reporting workflow",
      tags: ["phishing", "email", "workflow"],
      path: "skills/external/phishing/SKILL.md",
      sourceType: "external",
    },
  ];
}

function relevantSkills(): SkillIndexEntry[] {
  return [
    {
      name: "testing-api-for-broken-object-level-authorization",
      description: "Test API routes for broken object level authorization",
      tags: ["api", "authorization", "owasp"],
      path: "skills/external/api-bola/SKILL.md",
      sourceType: "external",
    },
    {
      name: "detecting-hardcoded-secrets-in-config",
      description: "Find secrets in env and config files",
      tags: ["secret", "credential", "env"],
      path: "skills/external/secrets/SKILL.md",
      sourceType: "external",
    },
    {
      name: "reviewing-auth-middleware-coverage",
      description: "Review login and auth middleware coverage",
      tags: ["auth", "authentication", "access-control", "login"],
      path: "skills/external/auth/SKILL.md",
      sourceType: "external",
    },
  ];
}

afterEach(() => {
  while (tempRoots.length > 0) {
    rmSync(tempRoots.pop()!, { recursive: true, force: true });
  }
});

describe("collectRepoEvidence", () => {
  it("ignores vendored skills paths when collecting keywords", () => {
    const report = tsCliReport("/tmp/project");
    report.inventory.files.push({
      path: "skills/external/Anthropic-Cybersecurity-Skills/skills/auditing-kubernetes-rbac-privilege-escalation/SKILL.md",
      category: "markdown",
    });

    const evidence = collectRepoEvidence(report);

    expect(evidence.detectedDomains.has("kubernetes")).toBe(false);
    expect(evidence.keywords.has("kubernetes")).toBe(false);
    expect(evidence.hasApiSurfaces).toBe(true);
    expect(evidence.hasAuthSurfaces).toBe(true);
  });
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
    expect(selected[0].reasons[0]).toMatch(/route:|auth surface:|stack:|source file:/);
    expect(selected[0].agentTypes).toContain("auth");
  });

  it("excludes irrelevant cloud, firmware, and phishing skills for a TS CLI repo", () => {
    const report = tsCliReport("/tmp/project");
    const selected = routeSkills(report, { skills: [...relevantSkills(), ...irrelevantSkills()] });
    const names = selected.map((skill) => skill.name);

    expect(names).toContain("reviewing-auth-middleware-coverage");
    expect(names).toContain("testing-api-for-broken-object-level-authorization");
    expect(names).not.toContain("post-exploiting-microsoft-graph-with-graphrunner");
    expect(names).not.toContain("auditing-kubernetes-rbac-privilege-escalation");
    expect(names).not.toContain("auditing-uefi-firmware-with-chipsec");
    expect(names).not.toContain("building-phishing-reporting-button-workflow");
  });

  it("does not route a skill based only on its own name tokens", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);
    const selection = scoreSkill(
      {
        name: "implementing-continuous-security-validation-with-bas",
        description: "Generic security validation",
        tags: ["security", "validation"],
        path: "skills/external/bas/SKILL.md",
        sourceType: "external",
      },
      evidence,
    );

    expect(selection).toBeNull();
  });

  it("cites concrete repo evidence in route reasons", () => {
    const report = tsCliReport("/tmp/project");
    const selected = routeSkills(report, { skills: relevantSkills() });
    const authSkill = selected.find((skill) => skill.name === "reviewing-auth-middleware-coverage");

    expect(authSkill).toBeDefined();
    expect(authSkill?.reasons.some((reason) => reason.includes("/api/login"))).toBe(true);
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
      ["auth", "login"],
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
