"""Tests for verified finding deduplication."""

from __future__ import annotations

from dataclasses import replace

from cyber_swarm.agents.specialists.base import evidence_from_context, static_reproduction
from cyber_swarm.models.agents import RankingRationale, VerifiedFinding
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.verifier.dedup import dedupe_verified_findings


def _ranking() -> RankingRationale:
    return RankingRationale(
        impact=0.5,
        exploitability=0.5,
        confidence=0.5,
        surface_sensitivity=0.5,
        verification_strength=0.5,
        mock_destructive_potential=0.0,
        total_score=0.5,
        factors=["test"],
    )


def _verified_finding(
    *,
    draft_id: str,
    specialist: str,
    agent_type: str,
    vulnerability_class: str,
    claim: str,
) -> VerifiedFinding:
    context = RetrievedContext(
        id=f"context-{draft_id}",
        query_id="q1",
        source_type="file",
        excerpt="export function requireAuth() {}",
        score=0.8,
        reason="auth",
        source_path="src/auth.ts",
        context_category="auth",
    )
    evidence = evidence_from_context(context, "Auth middleware context")
    return VerifiedFinding(
        id=f"verified-{draft_id}",
        title="Access control review",
        vulnerability_class=vulnerability_class,
        claim=claim,
        affected_surfaces=["/api/login"],
        affected_files=["src/auth.ts"],
        evidence=[evidence],
        impact_hypothesis="Unauthorized access",
        attack_path="Review auth middleware",
        safe_reproduction=static_reproduction(
            ["Inspect auth middleware in src/auth.ts"],
            "Document missing auth checks",
        ),
        confidence="medium",
        severity="medium",
        ranking_rationale=_ranking(),
        contributing_agents=[agent_type],
        contributing_specialists=[specialist],
        selected_skills=["example-skill"],
        retrieval_trace=[context.id],
        source_draft_ids=[draft_id],
    )


def test_dedupe_collapses_auth_and_api_duplicates_on_same_route():
    auth = _verified_finding(
        draft_id="draft-auth-1",
        specialist="auth-breaker",
        agent_type="auth",
        vulnerability_class="broken-access-control",
        claim=(
            "Static auth middleware evidence on login route handlers should enforce access control "
            "before sensitive API routes are reached."
        ),
    )
    api = _verified_finding(
        draft_id="draft-api-1",
        specialist="api-abuse",
        agent_type="api",
        vulnerability_class="api-abuse",
        claim=(
            "Static route handler evidence on login API endpoints should enforce authorization "
            "before processing sensitive requests."
        ),
    )

    deduped, merged_count = dedupe_verified_findings([auth, api])

    assert len(deduped) == 1
    assert merged_count == 1
    finding = deduped[0]
    assert set(finding.contributing_specialists) == {"auth-breaker", "api-abuse"}
    assert set(finding.contributing_agents) == {"auth", "api"}
    assert len(finding.source_draft_ids) == 2


def test_dedupe_preserves_distinct_root_causes():
    first = _verified_finding(
        draft_id="draft-secrets-1",
        specialist="secrets-config",
        agent_type="secrets",
        vulnerability_class="secret-exposure",
        claim="Configuration files contain credential-like keys that should not live in the repository.",
    )
    second = replace(
        first,
        id="verified-draft-secrets-2",
        source_draft_ids=["draft-secrets-2"],
        affected_surfaces=[".env"],
        affected_files=[".env"],
        vulnerability_class="secret-exposure",
    )

    deduped, merged_count = dedupe_verified_findings([first, second])

    assert len(deduped) == 2
    assert merged_count == 0
