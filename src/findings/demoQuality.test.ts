import { describe, expect, it } from "vitest";

import type { VerifiedFinding } from "./types";
import { sampleFindingsReport } from "./fixtures";
import {
  assessDemoQuality,
  filterDemoFindings,
  isDemoReady,
  isGenericPublicRouteFinding,
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
  it("treats /api/health lacks auth as generic public route noise", () => {
    expect(isGenericPublicRouteFinding(healthAuthFinding())).toBe(true);
  });

  it("treats /api/health lacks validation as generic public route noise", () => {
    expect(isGenericPublicRouteFinding(healthValidationFinding())).toBe(true);
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
