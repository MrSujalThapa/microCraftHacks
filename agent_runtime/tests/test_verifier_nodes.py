"""Tests for verifier LangGraph nodes."""

from __future__ import annotations

from cyber_swarm.graph.verifier_nodes import rank_node
from cyber_swarm.models.agents import (
    Confidence,
    EvidenceRef,
    RankingRationale,
    SafeReproduction,
    Severity,
    VerifiedFinding,
)


def _verified_finding() -> VerifiedFinding:
    return VerifiedFinding(
        id="verified-secret-1",
        title="Committed secret in backend/.env",
        vulnerability_class="secret-exposure",
        claim="backend/.env exposed SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET> in source control.",
        affected_surfaces=["backend/.env"],
        affected_files=["backend/.env"],
        evidence=[
            EvidenceRef(
                type="file",
                explanation="backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>.",
                path="backend/.env",
                line_start=1,
                line_end=1,
                snippet="SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
            )
        ],
        impact_hypothesis="Exposed service role key enables privileged access.",
        attack_path="Read backend/.env from repository history.",
        safe_reproduction=SafeReproduction(
            mode="static-proof",
            steps=["Open backend/.env and confirm the service role key line."],
            expected_result="Secret key line is present in tracked file.",
            safety_notes=[],
        ),
        confidence="high",
        severity="critical",
        ranking_rationale=RankingRationale(
            impact=0.95,
            exploitability=0.35,
            confidence=1.0,
            surface_sensitivity=0.9,
            verification_strength=0.8,
            mock_destructive_potential=0.0,
            total_score=0.82,
            factors=["secret exposure"],
        ),
        contributing_agents=["secrets"],
        contributing_specialists=["secrets-config"],
        selected_skills=[],
        retrieval_trace=[],
        source_draft_ids=["draft-secret"],
    )


def test_rank_node_annotates_demo_quality():
    state = {
        "verified_findings": [_verified_finding()],
        "metrics": {},
    }

    result = rank_node(state)

    assert len(result["verified_findings"]) == 1
    finding = result["verified_findings"][0]
    assert finding.demo_ready is True
    assert finding.demo_reason
    assert result["metrics"]["risk_ranking"]["demoReadyCount"] == 1
