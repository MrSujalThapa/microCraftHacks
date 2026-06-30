import type { FindingsReport } from "./types";

export function sampleFindingsReport(): FindingsReport {
  return {
    version: 1,
    scanId: "2026-06-29T12-00-00-000Z",
    status: "completed",
    startedAt: "2026-06-29T12:00:00.000Z",
    completedAt: "2026-06-29T12:05:00.000Z",
    metrics: {
      summary: {
        verifiedCount: 1,
        rejectedCount: 1,
        needsEvidenceCount: 0,
        severityCounts: { high: 1 },
      },
    },
    verifiedFindings: [
      {
        id: "verified-draft-auth-1",
        title: "Missing auth guard on /api/login handler",
        vulnerability_class: "broken-access-control",
        claim:
          "The /api/login handler in src/auth.ts lacks requireAuth() enforcement before request processing.",
        affected_surfaces: ["/api/login"],
        affected_files: ["src/auth.ts"],
        evidence: [
          {
            type: "file",
            explanation:
              "requireAuth() middleware in src/auth.ts is not invoked on the /api/login handler before request processing.",
            path: "src/auth.ts",
            route: "/api/login",
            line_start: 12,
            line_end: 28,
            snippet: "export function requireAuth(req, res, next) { /* guard */ }",
            evidence_pack_id: "ep-001",
            symbol: "requireAuth",
          },
        ],
        impact_hypothesis: "Unauthenticated requests can reach the login handler logic.",
        attack_path: "Trace middleware registration for /api/login in src/auth.ts.",
        safe_reproduction: {
          mode: "static-proof",
          steps: ["Open src/auth.ts and trace middleware registration for /api/login."],
          expected_result: "Guard invocation is absent on the login handler path.",
          safety_notes: ["No live exploit execution."],
        },
        confidence: "medium",
        severity: "high",
        ranking_rationale: {
          impact: 0.8,
          exploitability: 0.7,
          confidence: 0.6,
          surface_sensitivity: 0.75,
          verification_strength: 0.7,
          mock_destructive_potential: 0.0,
          total_score: 0.71,
          factors: ["High-impact auth surface", "Static evidence verified"],
        },
        contributing_agents: ["auth"],
        contributing_specialists: ["auth-breaker"],
        selected_skills: ["example-skill"],
        retrieval_trace: ["context-draft-auth-1"],
        source_draft_ids: ["draft-auth-1"],
      },
    ],
    rejectedFindings: [
      {
        draft_id: "draft-unsupported",
        title: "Speculative issue",
        reason: "Missing evidence refs",
        failed_checks: ["missing evidence refs"],
        source: "verifier",
      },
    ],
    needsMoreEvidenceFindings: [],
    capabilityDrafts: [],
    errors: [],
  };
}
