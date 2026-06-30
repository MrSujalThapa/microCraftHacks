"""Tests for verified finding risk ranking."""

from __future__ import annotations

from cyber_swarm.agents.specialists.base import evidence_from_context, static_reproduction
from cyber_swarm.models.agents import RankingRationale, VerifiedFinding
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.verifier.ranking import rank_verified_findings, severity_counts


def _ranking() -> RankingRationale:
    return RankingRationale(
        impact=0.0,
        exploitability=0.0,
        confidence=0.0,
        surface_sensitivity=0.0,
        verification_strength=0.0,
        mock_destructive_potential=0.0,
        total_score=0.0,
        factors=["pending"],
    )


def _finding(
    *,
    draft_id: str,
    vulnerability_class: str,
    confidence: str = "medium",
    mode: str = "static-proof",
) -> VerifiedFinding:
    context = RetrievedContext(
        id=f"context-{draft_id}",
        query_id="q1",
        source_type="file",
        excerpt="API_KEY=[REDACTED]",
        score=0.9,
        reason="config",
        source_path=".env",
        context_category="config",
    )
    evidence = evidence_from_context(context, "Configuration excerpt with credential-like keys")
    reproduction = static_reproduction(
        ["Review .env for credential-like keys"],
        "Document exposed secrets without exfiltration",
    )
    if mode != "static-proof":
        from dataclasses import replace

        reproduction = replace(reproduction, mode=mode)  # type: ignore[arg-type]

    return VerifiedFinding(
        id=f"verified-{draft_id}",
        title="Secret exposure" if vulnerability_class == "secret-exposure" else "Access control gap",
        vulnerability_class=vulnerability_class,
        claim=(
            "Configuration files contain credential-like keys that should not live in the repository."
            if vulnerability_class == "secret-exposure"
            else "Auth middleware on login route handlers should enforce access control before sensitive API routes."
        ),
        affected_surfaces=[".env"] if vulnerability_class == "secret-exposure" else ["/api/login"],
        affected_files=[".env"] if vulnerability_class == "secret-exposure" else ["src/auth.ts"],
        evidence=[evidence],
        impact_hypothesis=(
            "Exposed secrets enable credential theft."
            if vulnerability_class == "secret-exposure"
            else "Missing auth checks could allow unauthorized API access."
        ),
        attack_path="Inspect config files" if vulnerability_class == "secret-exposure" else "Review auth middleware",
        safe_reproduction=reproduction,
        confidence=confidence,  # type: ignore[arg-type]
        severity="medium",
        ranking_rationale=_ranking(),
        contributing_agents=["secrets" if vulnerability_class == "secret-exposure" else "auth"],
        contributing_specialists=[
            "secrets-config" if vulnerability_class == "secret-exposure" else "auth-breaker"
        ],
        selected_skills=["example-skill"],
        retrieval_trace=[context.id],
        source_draft_ids=[draft_id],
    )


def test_ranking_sorts_secret_exposure_above_access_control():
    secret = _finding(draft_id="draft-secrets-1", vulnerability_class="secret-exposure", confidence="high")
    auth = _finding(draft_id="draft-auth-1", vulnerability_class="broken-access-control", confidence="medium")

    ranked = rank_verified_findings([auth, secret])

    assert ranked[0].vulnerability_class == "secret-exposure"
    assert ranked[0].severity in {"critical", "high"}
    assert ranked[0].ranking_rationale.total_score > ranked[1].ranking_rationale.total_score


def test_secret_exposure_severity_override_factor_is_explainable():
    secret = _finding(draft_id="draft-secrets-1", vulnerability_class="secret-exposure", confidence="high")
    ranked = rank_verified_findings([secret])[0]

    assert ranked.severity == "critical"
    severity_factor = ranked.ranking_rationale.factors[-1]
    assert "secret-exposure" in severity_factor
    assert "overrides numeric score" in severity_factor
    assert "total score=" not in severity_factor


def test_severity_counts_and_sorted_output():
    findings = rank_verified_findings(
        [
            _finding(draft_id="draft-auth-1", vulnerability_class="broken-access-control"),
            _finding(draft_id="draft-secrets-1", vulnerability_class="secret-exposure", confidence="high"),
        ]
    )
    counts = severity_counts(findings)

    assert sum(counts.values()) == len(findings)
    assert counts["critical"] + counts["high"] >= 1
    assert findings[0].severity in {"critical", "high"}
