export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface GraphPathRef {
  source_node_id: string;
  sink_node_id: string;
  trust_boundary_crossed: string;
  attacker_controlled_input?: string;
  missing_guard?: string;
  edge_ids: string[];
  path_description: string;
}

export interface QaComparison {
  why_qa_may_miss: string;
  why_review_may_miss: string;
  suggested_regression_test: string;
}

export interface AttackGraphNode {
  id: string;
  node_type: string;
  label: string;
  path?: string;
  line_start?: number;
  line_end?: number;
  route?: string;
  symbol?: string;
  evidence_pack_id?: string;
}

export interface AttackGraphEdge {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: string;
  label: string;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface EvidenceRef {
  type: string;
  explanation: string;
  path?: string;
  route?: string;
  line_start?: number;
  line_end?: number;
  snippet?: string;
  evidence_pack_id?: string;
  symbol?: string;
}

export interface EvidencePack {
  id: string;
  path: string;
  line_start: number;
  line_end: number;
  snippet: string;
  symbol?: string;
  surface_type: string;
  kind: string;
  route?: string;
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
  demo_ready?: boolean;
  demo_reason?: string;
  graph_path?: GraphPathRef;
  qa_comparison?: QaComparison;
}

export interface RejectedFinding {
  draft_id?: string;
  title?: string;
  reason: string;
  failed_checks?: string[];
  missing_evidence?: string[];
  evidence?: EvidenceRef[];
  source?: string;
}

export interface FindingsReport {
  version: number;
  scanId: string;
  status: string;
  startedAt: string;
  completedAt: string;
  evidencePacks?: EvidencePack[];
  metrics: {
    summary?: {
      verifiedCount?: number;
      rejectedCount?: number;
      needsEvidenceCount?: number;
      severityCounts?: Partial<Record<Severity, number>>;
      demoReadyCount?: number;
    };
    [key: string]: unknown;
  };
  verifiedFindings: VerifiedFinding[];
  rejectedFindings: RejectedFinding[];
  needsMoreEvidenceFindings?: unknown[];
  capabilityDrafts?: unknown[];
  errors?: unknown[];
  attackGraph?: AttackGraph;
}
