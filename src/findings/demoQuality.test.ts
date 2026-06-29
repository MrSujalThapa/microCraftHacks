import { describe, expect, it } from "vitest";

import type { VerifiedFinding } from "./types";
import { sampleFindingsReport } from "./fixtures";
import {
  assessDemoQuality,
  filterDemoFindings,
  isDemoReady,
  isGenericDemoNoiseFinding,
  isGenericPublicRouteFinding,
  isGenericReadonlyGetFinding,
} from "./demoQuality";
import { formatFindingsTable } from "./display";

function healthAuthFinding(overrides: Partial<VerifiedFinding> = {}): VerifiedFinding {
  const base = sampleFindingsReport().verifiedFindings[0]!;
  return {
    ...base,
    id: "verified-health-auth",
    title: "Route /api/health handler lacks visible auth dependency",
    vulnerability_class: "broken-access-control",
    claim:
      "The health handler in src/server.ts exposes /api/health without a visible get_current_user, Depends(auth), or equivalent guard.",
    affected_surfaces: ["/api/health"],
    affected_files: ["src/server.ts"],
    evidence: [
      {
        type: "file",
        explanation:
          "health in src/server.ts:1 defines route /api/health without a visible auth dependency in the handler signature.",
        path: "src/server.ts",
        route: "/api/health",
        line_start: 1,
        line_end: 3,
        snippet: "app.get('/api/health', () => res.json({ ok: true }))",
        evidence_pack_id: "ep-health-auth",
        symbol: "health",
      },
    ],
    safe_reproduction: {
      mode: "static-proof",
      steps: ["Open src/server.ts:1 and inspect the health handler signature."],
      expected_result: "Handler for /api/health lacks visible auth enforcement in static code.",
      safety_notes: [],
    },
    demo_ready: true,
    ...overrides,
  };
}

function healthValidationFinding(overrides: Partial<VerifiedFinding> = {}): VerifiedFinding {
  const base = healthAuthFinding();
  return {
    ...base,
    id: "verified-health-validation",
    title: "/api/health handler lacks visible validation in src/server.ts",
    claim:
      "The health handler in src/server.ts processes /api/health requests and lacks input validation or authorization checks.",
    evidence: [
      {
        type: "file",
        explanation:
          "health in src/server.ts:1 handles /api/health requests and lacks schema validation or authorization checks.",
        path: "src/server.ts",
        route: "/api/health",
        line_start: 1,
        line_end: 3,
        snippet: "app.get('/api/health', () => res.json({ ok: true }))",
        evidence_pack_id: "ep-health-validation",
        symbol: "health",
      },
    ],
    safe_reproduction: {
      mode: "static-proof",
      steps: ["Open src/server.ts:1 and inspect the health handler body."],
      expected_result: "Handler for /api/health lacks visible validation in static code.",
      safety_notes: [],
    },
    ...overrides,
  };
}

describe("isGenericPublicRouteFinding", () => {
  it("treats /api/health lacks auth as generic demo noise", () => {
    expect(isGenericDemoNoiseFinding(healthAuthFinding())).toBe(true);
  });

  it("treats /api/health lacks validation as generic demo noise", () => {
    expect(isGenericDemoNoiseFinding(healthValidationFinding())).toBe(true);
  });

  it("treats /api/zones readonly GET validation as generic demo noise", () => {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    const finding: VerifiedFinding = {
      ...base,
      id: "verified-zones-validation",
      title: "/api/zones handler lacks visible validation in backend/app/main.py",
      vulnerability_class: "broken-access-control",
      claim:
        "The list_zones handler in backend/app/main.py processes /api/zones requests and lacks input validation.",
      affected_surfaces: ["/api/zones"],
      affected_files: ["backend/app/main.py"],
      evidence: [
        {
          type: "file",
          explanation:
            "list_zones in backend/app/main.py:42 handles /api/zones requests and lacks schema validation.",
          path: "backend/app/main.py",
          route: "/api/zones",
          line_start: 42,
          line_end: 48,
          snippet: "@app.get('/api/zones')\nasync def list_zones():\n    return {'zones': []}",
          evidence_pack_id: "ep-zones",
          symbol: "list_zones",
        },
      ],
      confidence: "high",
      ranking_rationale: { ...base.ranking_rationale, total_score: 0.82 },
      demo_ready: true,
    };

    expect(isGenericReadonlyGetFinding(finding)).toBe(true);
    expect(isDemoReady(finding)).toBe(false);
  });

  it("allows health route findings with sensitive exposure", () => {
    const finding = healthAuthFinding({
      title: "/api/health exposes SUPABASE_SERVICE_ROLE_KEY in response body",
      claim: "The /api/health handler returns SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET> in JSON.",
      evidence: [
        {
          type: "file",
          explanation: "health response includes service role key material.",
          path: "src/server.ts",
          route: "/api/health",
          line_start: 1,
          snippet: "return res.json({ serviceRole: process.env.SUPABASE_SERVICE_ROLE_KEY })",
          evidence_pack_id: "ep-health-secret",
        },
      ],
    });

    expect(isGenericPublicRouteFinding(finding)).toBe(false);
  });
});

describe("isDemoReady", () => {
  it("marks /api/health auth gap as not demo-ready even when demo_ready flag is true", () => {
    expect(isDemoReady(healthAuthFinding({ demo_ready: true }))).toBe(false);
  });

  it("marks /api/health validation gap as not demo-ready even when demo_ready flag is true", () => {
    expect(isDemoReady(healthValidationFinding({ demo_ready: true }))).toBe(false);
  });

  it("marks secret exposure as demo-ready", () => {
    const assessment = assessDemoQuality({
      ...healthAuthFinding(),
      id: "verified-secret",
      title: "Committed secret in backend/.env",
      vulnerability_class: "secret-exposure",
      claim: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
      affected_surfaces: ["backend/.env"],
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          path: "backend/.env",
          line_start: 1,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
          evidence_pack_id: "ep-secret",
        },
      ],
    });
    expect(assessment.demoReady).toBe(true);
  });
});

describe("filterDemoFindings", () => {
  it("hides health noise and keeps secret findings for demo output", () => {
    const secretFinding: VerifiedFinding = {
      ...healthAuthFinding(),
      id: "verified-secret",
      title: "Committed secret in backend/.env",
      vulnerability_class: "secret-exposure",
      claim: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
      affected_surfaces: ["backend/.env"],
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          path: "backend/.env",
          line_start: 1,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
          evidence_pack_id: "ep-secret",
        },
      ],
      demo_ready: true,
    };

    const filtered = filterDemoFindings([
      healthAuthFinding(),
      healthValidationFinding(),
      secretFinding,
    ]);

    expect(filtered).toHaveLength(1);
    expect(filtered[0]?.id).toBe("verified-secret");
  });
});

describe("wattif report shapes", () => {
  function sparseHealthFinding(
    id: string,
    title: string,
    overrides: Partial<VerifiedFinding> = {},
  ): VerifiedFinding {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    return {
      ...base,
      id,
      title,
      vulnerability_class: "broken-access-control",
      claim: title,
      affected_surfaces: [],
      affected_files: ["backend/app/routes/health.py"],
      evidence: [
        {
          type: "file",
          explanation: title,
          path: "backend/app/routes/health.py",
          line_start: 12,
          line_end: 18,
          evidence_pack_id: `ep-${id}`,
        },
      ],
      confidence: "high",
      ranking_rationale: {
        ...base.ranking_rationale,
        total_score: 0.82,
      },
      demo_ready: true,
      ...overrides,
    };
  }

  function wattifSecretFinding(): VerifiedFinding {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    return {
      ...base,
      id: "verified-draft-h1",
      title: "Hardcoded SUPABASE_SERVICE_ROLE_KEY in backend/.env",
      vulnerability_class: "secret-exposure",
      claim:
        "SUPABASE_SERVICE_ROLE_KEY in backend/.env:4 is assigned in tracked configuration without using a secret manager.",
      affected_surfaces: [],
      affected_files: ["backend/.env"],
      evidence: [
        {
          type: "file",
          explanation:
            "SUPABASE_SERVICE_ROLE_KEY appears in backend/.env:4 with a credential-like assignment.",
          path: "backend/.env",
          line_start: 4,
          line_end: 4,
          snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
          evidence_pack_id: "ep-secret-h1",
          symbol: "SUPABASE_SERVICE_ROLE_KEY",
        },
      ],
      confidence: "high",
      severity: "critical",
      demo_ready: true,
    };
  }

  it("hides sparse /api/health auth finding with exact wattif title", () => {
    const finding = sparseHealthFinding(
      "verified-draft-auth-health",
      "/api/health handler lacks visible auth dependency",
    );
    expect(isDemoReady(finding)).toBe(false);
  });

  it("hides sparse /api/health validation finding with exact wattif title", () => {
    const finding = sparseHealthFinding(
      "verified-draft-validation-health",
      "/api/health handler lacks visible validation in backend/app/routes/health.py",
    );
    expect(isDemoReady(finding)).toBe(false);
  });

  it("findings --demo keeps only verified-draft-h1 for wattif report shape", () => {
    const base = sampleFindingsReport().verifiedFindings[0]!;
    const zonesFinding: VerifiedFinding = {
      ...base,
      id: "verified-zones-validation",
      title: "/api/zones handler lacks visible validation in backend/app/main.py",
      vulnerability_class: "broken-access-control",
      claim: "/api/zones handler lacks visible validation in backend/app/main.py",
      affected_surfaces: [],
      affected_files: ["backend/app/main.py"],
      evidence: [
        {
          type: "file",
          explanation: "/api/zones handler lacks visible validation in backend/app/main.py",
          path: "backend/app/main.py",
          line_start: 42,
          snippet: "@app.get('/api/zones')\nasync def list_zones(): pass",
          evidence_pack_id: "ep-zones",
        },
      ],
      confidence: "high",
      ranking_rationale: { ...base.ranking_rationale, total_score: 0.82 },
      demo_ready: true,
    };

    const report = {
      ...sampleFindingsReport(),
      verifiedFindings: [
        sparseHealthFinding(
          "verified-draft-auth-health",
          "/api/health handler lacks visible auth dependency",
        ),
        sparseHealthFinding(
          "verified-draft-validation-health",
          "/api/health handler lacks visible validation in backend/app/routes/health.py",
        ),
        zonesFinding,
        wattifSecretFinding(),
      ],
      metrics: {
        summary: {
          verifiedCount: 3,
          rejectedCount: 0,
          demoReadyCount: 3,
        },
      },
    };

    const output = formatFindingsTable(report, "wattif-findings.json", { demoOnly: true });
    expect(output).toContain("verified-draft-h1");
    expect(output).not.toContain("verified-draft-auth-health");
    expect(output).not.toContain("verified-draft-validation-health");
    expect(output).not.toContain("lacks visible auth");
    expect(output).not.toContain("verified-zones-validation");
    expect(output).not.toContain("/api/zones");
  });
});

describe("formatFindingsTable demoOnly", () => {
  it("shows only demo-ready findings and hides /api/health noise", () => {
    const report = {
      ...sampleFindingsReport(),
      verifiedFindings: [
        healthAuthFinding(),
        healthValidationFinding(),
        {
          ...healthAuthFinding(),
          id: "verified-secret",
          title: "Committed secret in backend/.env",
          vulnerability_class: "secret-exposure",
          claim: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
          affected_surfaces: ["backend/.env"],
          affected_files: ["backend/.env"],
          evidence: [
            {
              type: "file",
              explanation: "backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
              path: "backend/.env",
              line_start: 1,
              snippet: "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
              evidence_pack_id: "ep-secret",
            },
          ],
          demo_ready: true,
        },
      ],
      metrics: {
        summary: {
          verifiedCount: 3,
          rejectedCount: 0,
          demoReadyCount: 1,
        },
      },
    };

    const output = formatFindingsTable(report, "report.json", { demoOnly: true });
    expect(output).toContain("verified-secret");
    expect(output).not.toContain("verified-health-auth");
    expect(output).not.toContain("verified-health-validation");
    expect(output).not.toContain("lacks visible auth");
    expect(output).not.toContain("lacks visible validation");
  });
});
