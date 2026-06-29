"""Tests for demo-readiness quality gate."""

from __future__ import annotations

from dataclasses import replace

from cyber_swarm.agents.specialists.base import static_reproduction
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.models.agents import AgentFindingDraft, RankingRationale, VerifiedFinding
from cyber_swarm.verifier.demo_quality import (
    assess_demo_quality,
    is_generic_public_route_finding,
    public_route_verification_failures,
)
from cyber_swarm.verifier.verify import verify_draft


def _health_pack() -> EvidencePack:
    return EvidencePack(
        id="ep-health",
        path="src/server.ts",
        line_start=1,
        line_end=3,
        snippet="app.get('/api/health', () => res.json({ ok: true }))",
        symbol="health",
        surface_type="api",
        kind="route_handler",
        route="/api/health",
    )


def _health_draft() -> AgentFindingDraft:
    pack = _health_pack()
    evidence = evidence_from_pack(
        pack,
        explanation="The /api/health handler lacks authentication and input validation middleware.",
    )
    return AgentFindingDraft(
        id="draft-health",
        title="Missing auth on /api/health",
        vulnerability_class="broken-access-control",
        claim="The /api/health endpoint lacks authentication and validation before responding.",
        affected_surfaces=["/api/health"],
        evidence=[evidence],
        impact_hypothesis="Health endpoint is reachable without auth.",
        attack_path="Request GET /api/health without credentials.",
        safe_reproduction=static_reproduction(
            ["Open src/server.ts and inspect the /api/health handler."],
            "Handler responds without auth middleware.",
        ),
        confidence="medium",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=[],
        retrieval_trace=[],
    )


def _scan_report() -> dict:
    return {
        "inventory": {"files": [{"path": "src/server.ts", "category": "typescript"}]},
        "surfaces": {"api": [{"path": "/api/health", "file": "src/server.ts"}]},
    }


def _visible_auth_health_draft() -> AgentFindingDraft:
    pack = _health_pack()
    evidence = evidence_from_pack(
        pack,
        explanation=(
            "health in src/server.ts:1 defines route /api/health without a visible "
            "auth dependency in the handler signature."
        ),
    )
    return AgentFindingDraft(
        id="draft-health-auth",
        title="Route /api/health handler lacks visible auth dependency",
        vulnerability_class="broken-access-control",
        claim=(
            "The health handler in src/server.ts exposes /api/health without a visible "
            "get_current_user, Depends(auth), or equivalent guard in the static handler definition."
        ),
        affected_surfaces=["/api/health"],
        evidence=[evidence],
        impact_hypothesis="Missing auth dependency on the handler can allow unauthenticated access to the route.",
        attack_path="Review src/server.ts:1 for auth dependencies on /api/health.",
        safe_reproduction=static_reproduction(
            [
                "Open src/server.ts:1 and inspect the health handler signature.",
                "Confirm /api/health does not declare an auth dependency before business logic.",
            ],
            "Handler for /api/health lacks visible auth enforcement in static code.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=[],
        retrieval_trace=[],
    )


def _visible_validation_health_draft() -> AgentFindingDraft:
    pack = _health_pack()
    evidence = evidence_from_pack(
        pack,
        explanation=(
            "health in src/server.ts:1 handles /api/health requests and lacks schema validation "
            "or authorization checks in the static handler definition."
        ),
    )
    return AgentFindingDraft(
        id="draft-health-validation",
        title="/api/health handler lacks visible validation in src/server.ts",
        vulnerability_class="broken-access-control",
        claim=(
            "The health handler in src/server.ts processes /api/health requests and "
            "lacks input validation or authorization checks in the static handler definition."
        ),
        affected_surfaces=["/api/health"],
        evidence=[evidence],
        impact_hypothesis="Missing validation on the handler can enable abusive or malformed request processing.",
        attack_path="Review src/server.ts:1 for validation and auth checks on /api/health.",
        safe_reproduction=static_reproduction(
            [
                "Open src/server.ts:1 and inspect the health handler body.",
                "Confirm /api/health lacks visible schema validation before processing.",
            ],
            "Handler for /api/health lacks visible validation in static code.",
        ),
        confidence="medium",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=[],
        retrieval_trace=[],
    )


def test_visible_auth_health_route_is_not_demo_ready():
    draft = _visible_auth_health_draft()
    assert is_generic_public_route_finding(draft) is True


def test_visible_validation_health_route_is_not_demo_ready():
    draft = _visible_validation_health_draft()
    assert is_generic_public_route_finding(draft) is True


def test_verify_rejects_visible_auth_health_route_finding():
    draft = _visible_auth_health_draft()
    result = verify_draft(
        draft,
        _scan_report(),
        context_paths={"src/server.ts"},
        evidence_packs=[_health_pack()],
    )
    assert result.status == "rejected"


def test_verify_rejects_visible_validation_health_route_finding():
    draft = _visible_validation_health_draft()
    result = verify_draft(
        draft,
        _scan_report(),
        context_paths={"src/server.ts"},
        evidence_packs=[_health_pack()],
    )
    assert result.status == "rejected"


def test_health_route_with_sensitive_exposure_is_not_generic():
    draft = replace(
        _visible_auth_health_draft(),
        title="/api/health exposes SUPABASE_SERVICE_ROLE_KEY in response body",
        claim="The /api/health handler returns SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET> in JSON.",
    )
    assert is_generic_public_route_finding(draft) is False


def test_generic_health_route_is_not_demo_ready():
    draft = _health_draft()
    assert is_generic_public_route_finding(draft) is True
    assert public_route_verification_failures(draft)


def test_verify_rejects_generic_health_route_finding():
    draft = _health_draft()
    result = verify_draft(
        draft,
        _scan_report(),
        context_paths={"src/server.ts"},
        evidence_packs=[_health_pack()],
    )
    assert result.status == "rejected"
    assert result.rejected is not None
    checks = " ".join(result.rejected.failed_checks).lower()
    assert "public health" in checks or "health/root" in checks


def test_secret_finding_assessment_is_demo_ready():
    finding = VerifiedFinding(
        id="verified-secret",
        title="Committed service role key in backend/.env",
        vulnerability_class="secret-exposure",
        claim="backend/.env contains SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET> in source control.",
        affected_surfaces=["backend/.env"],
        affected_files=["backend/.env"],
        evidence=[],
        impact_hypothesis="Exposed service role key enables privileged access.",
        attack_path="Read backend/.env from repository history.",
        safe_reproduction=static_reproduction(
            ["Open backend/.env and confirm the service role key line."],
            "Secret key line is present in tracked file.",
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
    demo_ready, reason = assess_demo_quality(finding)
    assert demo_ready is True
    assert "secret" in reason.lower()
