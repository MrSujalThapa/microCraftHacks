export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface EvidenceRef {
  type: string;
  explanation: string;
  path?: string;
  route?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
}

export interface SafeReproduction {
  mode: "static-proof" | "local-runtime" | "mock-destructive";
  steps: string[];
  expected_result: string;
  safety_notes: string[];
}

export interface RankingRationale {
  impact: number;
  exploitability: number;
  confidence: number;
  surface_sensitivity: number;
  verification_strength: number;
  mock_destructive_potential: number;
  total_score: number;
  factors: string[];
}

export interface VerifiedFinding {
  id: string;
  title: string;
  vulnerability_class: string;
  claim: string;
  affected_surfaces: string[];
  affected_files: string[];
  evidence: EvidenceRef[];
  impact_hypothesis: string;
  attack_path: string;
  safe_reproduction: SafeReproduction;
  confidence: Confidence;
  severity: Severity;
  ranking_rationale: RankingRationale;
  contributing_agents: string[];
  contributing_specialists: string[];
  selected_skills: string[];
  retrieval_trace: string[];
  source_draft_ids: string[];
}

export interface RejectedFinding {
  draft_id?: string;
  title?: string;
  reason: string;
  failed_checks?: string[];
  missing_evidence?: string[];
  source?: string;
}

export interface FindingsReport {
  version: number;
  scanId: string;
  status: string;
  startedAt: string;
  completedAt: string;
  metrics: {
    summary?: {
      verifiedCount?: number;
      rejectedCount?: number;
      needsEvidenceCount?: number;
      severityCounts?: Partial<Record<Severity, number>>;
    };
    [key: string]: unknown;
  };
  verifiedFindings: VerifiedFinding[];
  rejectedFindings: RejectedFinding[];
  needsMoreEvidenceFindings?: unknown[];
  capabilityDrafts?: unknown[];
  errors?: unknown[];
}
