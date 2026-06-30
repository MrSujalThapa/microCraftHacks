"""Agent output models for recon, planning, and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Confidence = Literal["high", "medium", "low"]
Priority = Literal["high", "medium", "low"]
Severity = Literal["critical", "high", "medium", "low", "info"]
VerificationStatus = Literal["verified", "rejected", "needs_more_evidence"]


@dataclass(frozen=True)
class TrustBoundary:
    boundary_type: str
    description: str
    files: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HighRiskSurface:
    surface_type: str
    path: str
    file: str
    reason: str


@dataclass(frozen=True)
class ReconReport:
    trust_boundaries: list[TrustBoundary]
    high_risk_surfaces: list[HighRiskSurface]
    selected_agent_targets: list[str]


@dataclass(frozen=True)
class AttackHypothesis:
    id: str
    agent_type: str
    specialist: str
    title: str
    vulnerability_class: str
    target_surfaces: list[str]
    target_files: list[str]
    reasoning: str
    required_evidence: list[str]
    priority: Priority


@dataclass(frozen=True)
class EvidenceRef:
    type: str
    explanation: str
    path: str | None = None
    route: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    evidence_pack_id: str | None = None
    symbol: str | None = None


@dataclass(frozen=True)
class SafeReproduction:
    mode: Literal["static-proof", "local-runtime", "mock-destructive"]
    steps: list[str]
    expected_result: str
    safety_notes: list[str]


@dataclass(frozen=True)
class AgentFindingDraft:
    id: str
    title: str
    vulnerability_class: str
    claim: str
    affected_surfaces: list[str]
    evidence: list[EvidenceRef]
    impact_hypothesis: str
    attack_path: str
    safe_reproduction: SafeReproduction
    confidence: Confidence
    agent_type: str
    specialist: str
    selected_skills: list[str]
    retrieval_trace: list[str]


@dataclass(frozen=True)
class RejectedFindingDraft:
    draft_id: str
    reason: str
    missing_evidence: list[str]


@dataclass(frozen=True)
class RankingRationale:
    impact: float
    exploitability: float
    confidence: float
    surface_sensitivity: float
    verification_strength: float
    mock_destructive_potential: float
    total_score: float
    factors: list[str]


@dataclass(frozen=True)
class VerifiedFinding:
    id: str
    title: str
    vulnerability_class: str
    claim: str
    affected_surfaces: list[str]
    affected_files: list[str]
    evidence: list[EvidenceRef]
    impact_hypothesis: str
    attack_path: str
    safe_reproduction: SafeReproduction
    confidence: Confidence
    severity: Severity
    ranking_rationale: RankingRationale
    contributing_agents: list[str]
    contributing_specialists: list[str]
    selected_skills: list[str]
    retrieval_trace: list[str]
    source_draft_ids: list[str]
    demo_ready: bool = False
    demo_reason: str = ""


@dataclass(frozen=True)
class VerifierRejectedFinding:
    draft_id: str
    title: str
    reason: str
    failed_checks: list[str]
    evidence: list[EvidenceRef] = field(default_factory=list)
    source: Literal["verifier"] = "verifier"


@dataclass(frozen=True)
class NeedsMoreEvidenceFinding:
    draft_id: str
    title: str
    reason: str
    missing_evidence: list[str]
