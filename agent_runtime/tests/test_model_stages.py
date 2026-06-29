"""Tests for model stage parsing helpers."""

from __future__ import annotations

from cyber_swarm.agents.model_stages import _canonical_specialist, _parse_hypotheses_payload
from cyber_swarm.models.agents import AttackHypothesis


def test_canonical_specialist_maps_agent_type():
    assert _canonical_specialist("auth", "Web Authentication Specialist") == "auth-breaker"
    assert _canonical_specialist("secrets", "Identity & Secrets Specialist") == "secrets-config"
    assert _canonical_specialist("api", "API Authorization Specialist") == "api-abuse"


def test_parse_hypotheses_payload_normalizes_specialists():
    fallback = [
        AttackHypothesis(
            id="hyp-fallback",
            agent_type="auth",
            specialist="auth-breaker",
            title="Fallback",
            vulnerability_class="broken-access-control",
            target_surfaces=["/api/login"],
            target_files=["src/auth.ts"],
            reasoning="fallback",
            required_evidence=["auth middleware"],
            priority="medium",
        )
    ]
    parsed = _parse_hypotheses_payload(
        {
            "hypotheses": [
                {
                    "id": "H-001",
                    "agent_type": "secrets",
                    "specialist": "Identity & Secrets Specialist",
                    "title": "Secret exposure",
                    "vulnerability_class": "secret-exposure",
                    "target_surfaces": [],
                    "target_files": [".env"],
                    "reasoning": "config boundary",
                    "required_evidence": ["config file"],
                    "priority": "high",
                }
            ]
        },
        fallback,
        3,
    )

    assert parsed[0].specialist == "secrets-config"
