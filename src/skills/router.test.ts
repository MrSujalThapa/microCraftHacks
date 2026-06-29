import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createDefaultConfig } from "../config/defaults";
import { walkRepo } from "../scanner/inventory";
import { mapSurfaces } from "../scanner/surfaces";
import type { ScanReport } from "../scanner/types";
import { buildSkillsIndex } from "./indexer";
import { collectRepoEvidence, passesEvidenceGates, routeSkills, routeSkillsFromReport, scoreSkill } from "./router";
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

function gatedSkills(): SkillIndexEntry[] {
  return [
    {
      name: "testing-websocket-authentication-bypass",
      description: "Websocket auth bypass testing",
      tags: ["websocket", "auth", "api"],
      path: "skills/external/websocket/SKILL.md",
      sourceType: "external",
    },
    {
      name: "detecting-credential-stuffing-on-login",
      description: "Credential stuffing detection on login endpoints",
      tags: ["credential-stuffing", "login", "auth"],
      path: "skills/external/stuffing/SKILL.md",
      sourceType: "external",
    },
    {
      name: "abusing-saas-sso-token-replay",
      description: "SaaS SSO OAuth token abuse",
      tags: ["sso", "oauth", "saas"],
      path: "skills/external/sso/SKILL.md",
      sourceType: "external",
    },
    {
      name: "testing-hardware-security-key-auth",
      description: "Hardware security key and passkey auth review",
      tags: ["webauthn", "passkey", "auth"],
      path: "skills/external/webauthn/SKILL.md",
      sourceType: "external",
    },
  ];
}

function specializedSkills(): SkillIndexEntry[] {
  return [
    {
      name: "configuring-multi-factor-authentication-with-duo",
      description: "Configure Duo MFA",
      tags: ["mfa", "duo", "authentication"],
      path: "skills/external/duo/SKILL.md",
      sourceType: "external",
    },
    {
      name: "implementing-mtls-for-zero-trust-services",
      description: "Mutual TLS for zero trust",
      tags: ["mtls", "tls", "authentication"],
      path: "skills/external/mtls/SKILL.md",
      sourceType: "external",
    },
    {
      name: "detecting-pass-the-hash-attacks",
      description: "Detect pass the hash in Windows AD environments",
      tags: ["pass-the-hash", "ntlm", "windows"],
      path: "skills/external/pth/SKILL.md",
      sourceType: "external",
    },
  ];
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

  it("does not treat generic provider paths as SSO evidence", () => {
    const report = tsCliReport("/tmp/project");
    report.inventory.files.push({ path: "src/config/provider.ts", category: "typescript" });

    const evidence = collectRepoEvidence(report);

    expect(evidence.hasSsoEvidence).toBe(false);
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

  it("excludes websocket skills without websocket evidence", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);

    expect(evidence.hasWebsocketEvidence).toBe(false);
    expect(passesEvidenceGates(gatedSkills()[0], evidence)).toBe(false);

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...gatedSkills()] });
    expect(selected.map((skill) => skill.name)).not.toContain("testing-websocket-authentication-bypass");
  });

  it("excludes hardware key skills without webauthn or passkey evidence", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);

    expect(evidence.hasWebauthnEvidence).toBe(false);
    expect(passesEvidenceGates(gatedSkills()[3], evidence)).toBe(false);

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...gatedSkills()] });
    expect(selected.map((skill) => skill.name)).not.toContain("testing-hardware-security-key-auth");
  });

  it("excludes SSO skills without oauth, saml, or sso evidence", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);

    expect(evidence.hasSsoEvidence).toBe(false);
    expect(passesEvidenceGates(gatedSkills()[2], evidence)).toBe(false);

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...gatedSkills()] });
    expect(selected.map((skill) => skill.name)).not.toContain("abusing-saas-sso-token-replay");
  });

  it("excludes credential stuffing skills without login plus abuse signals", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);

    expect(evidence.hasCredentialStuffingEvidence).toBe(false);
    expect(passesEvidenceGates(gatedSkills()[1], evidence)).toBe(false);

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...gatedSkills()] });
    expect(selected.map((skill) => skill.name)).not.toContain("detecting-credential-stuffing-on-login");
  });

  it("still selects API and auth skills when matching surfaces exist", () => {
    const report = tsCliReport("/tmp/project");
    const selected = routeSkills(report, { skills: [...relevantSkills(), ...gatedSkills()] });
    const names = selected.map((skill) => skill.name);

    expect(names).toContain("testing-api-for-broken-object-level-authorization");
    expect(names).toContain("reviewing-auth-middleware-coverage");
  });

  it("distributes scores instead of maxing every selected skill", () => {
    const report = tsCliReport("/tmp/project");
    const selected = routeSkills(report, { skills: relevantSkills() });

    expect(selected.length).toBeGreaterThan(1);
    const scores = selected.map((skill) => skill.score);
    expect(new Set(scores).size).toBeGreaterThan(1);
    expect(scores.every((score) => score === 1)).toBe(false);
    expect(scores.every((score) => score <= 0.95)).toBe(true);
  });

  it("excludes Duo, mTLS, and pass-the-hash skills without concrete evidence", () => {
    const report = tsCliReport("/tmp/project");
    const evidence = collectRepoEvidence(report);

    expect(evidence.hasMfaEvidence).toBe(false);
    expect(evidence.hasMtlsEvidence).toBe(false);
    expect(evidence.hasPassTheHashEvidence).toBe(false);

    for (const skill of specializedSkills()) {
      expect(passesEvidenceGates(skill, evidence)).toBe(false);
    }

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...specializedSkills()] });
    const names = selected.map((skill) => skill.name);
    expect(names).not.toContain("configuring-multi-factor-authentication-with-duo");
    expect(names).not.toContain("implementing-mtls-for-zero-trust-services");
    expect(names).not.toContain("detecting-pass-the-hash-attacks");
  });

  it("does not cite test files as route or auth evidence", () => {
    const report: ScanReport = {
      version: "0.1.0",
      scannedAt: new Date().toISOString(),
      projectRoot: "/tmp/project",
      inventory: {
        totalFiles: 1,
        byCategory: { typescript: 1 },
        files: [{ path: "src/server.ts", category: "typescript" }],
      },
      surfaces: {
        routes: [{ path: "/health", file: "src/scanner/surfaces.test.ts", framework: "express" }],
        api: [{ path: "/api/login", file: "src/scanner/surfaces.test.ts", framework: "express" }],
        auth: [{ file: "src/scanner/surfaces.test.ts", type: "middleware" }],
        dataModels: [],
      },
    };

    const evidence = collectRepoEvidence(report);

    expect(evidence.hasApiSurfaces).toBe(false);
    expect(evidence.hasAuthSurfaces).toBe(false);

    const selected = routeSkills(report, { skills: relevantSkills() });
    for (const skill of selected) {
      for (const reason of skill.reasons) {
        expect(reason).not.toContain(".test.ts");
        expect(reason).not.toContain(".spec.ts");
      }
    }
  });

  it("does not route API skills from test-only fixtures on this repo", () => {
    const projectRoot = join(__dirname, "..", "..");
    if (!existsSync(join(projectRoot, "package.json"))) {
      return;
    }

    const inventory = walkRepo(projectRoot);
    const surfaces = mapSurfaces(projectRoot, inventory);
    const report: ScanReport = {
      version: "0.1.0",
      scannedAt: new Date().toISOString(),
      projectRoot,
      inventory,
      surfaces,
    };

    const selected = routeSkills(report, { skills: [...relevantSkills(), ...specializedSkills()] }, 20);
    const names = selected.map((skill) => skill.name);

    expect(surfaces.api).toHaveLength(0);
    expect(names).not.toContain("testing-api-for-broken-object-level-authorization");
    expect(names).not.toContain("configuring-multi-factor-authentication-with-duo");
    expect(names).not.toContain("implementing-mtls-for-zero-trust-services");
    expect(names).not.toContain("detecting-pass-the-hash-attacks");

    for (const skill of selected) {
      for (const reason of skill.reasons) {
        expect(reason).not.toMatch(/\.test\.(ts|tsx|js|jsx)/);
        expect(reason).not.toMatch(/\.spec\.(ts|tsx|js|jsx)/);
      }
    }
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
