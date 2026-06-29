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
        title: "Auth boundary gap on login route",
        vulnerability_class: "broken-access-control",
        claim:
          "Static auth middleware evidence on login route handlers should enforce access control before sensitive API routes are reached.",
        affected_surfaces: ["/api/login"],
        affected_files: ["src/auth.ts"],
        evidence: [
          {
            type: "file",
            explanation: "Auth middleware context on login route handler",
            path: "src/auth.ts",
            route: "/api/login",
            line_start: 12,
            line_end: 28,
          },
        ],
        impact_hypothesis: "Missing auth checks could allow unauthorized API access.",
        attack_path: "Review auth middleware coverage for protected routes.",
        safe_reproduction: {
          mode: "static-proof",
          steps: ["Inspect auth middleware in src/auth.ts without live requests."],
          expected_result: "Document routes lacking auth enforcement.",
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
