"""Tests for draft finding verification."""

from __future__ import annotations

from dataclasses import replace

from cyber_swarm.agents.specialists.auth_breaker import run_auth_breaker
from cyber_swarm.agents.specialists.base import evidence_from_context, static_reproduction
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis, EvidenceRef
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceAuth,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.skills import RoutedSkills
from cyber_swarm.verifier.verify import verify_draft, verify_drafts


def _scan_report() -> dict:
    return {
        "inventory": {
            "files": [
                {"path": "src/auth.ts", "category": "typescript"},
                {"path": ".env", "category": "config"},
            ],
        },
        "surfaces": {
            "api": [{"path": "/api/login", "file": "src/auth.ts"}],
            "routes": [],
            "auth": [{"file": "src/auth.ts", "type": "middleware"}],
        },
    }


def _supported_pack() -> EvidencePack:
    return EvidencePack(
        id="ep-001",
        path="src/auth.ts",
        line_start=12,
        line_end=28,
        snippet="export function requireAuth(req, res, next) { /* guard */ }",
        symbol="requireAuth",
        surface_type="auth",
        kind="function",
        route="/api/login",
    )


def _supported_draft() -> AgentFindingDraft:
    pack = _supported_pack()
    evidence = evidence_from_pack(
        pack,
        explanation=(
            "requireAuth() middleware in src/auth.ts is not invoked on the /api/login handler "
            "before request processing."
        ),
    )
    return AgentFindingDraft(
        id="draft-auth-supported",
        title="Missing auth guard on /api/login handler",
        vulnerability_class="broken-access-control",
        claim=(
            "The /api/login handler in src/auth.ts lacks requireAuth() enforcement before "
            "request processing."
        ),
        affected_surfaces=["/api/login"],
        evidence=[evidence],
        impact_hypothesis="Unauthenticated requests can reach the login handler logic.",
        attack_path="Trace middleware registration for /api/login in src/auth.ts.",
        safe_reproduction=static_reproduction(
            ["Open src/auth.ts and trace middleware registration for /api/login."],
            "Guard invocation is absent on the login handler path.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=["example-skill"],
        retrieval_trace=["c1"],
    )


def _unsupported_draft() -> AgentFindingDraft:
    return AgentFindingDraft(
        id="draft-unsupported",
        title="Speculative issue",
        vulnerability_class="unknown",
        claim="Maybe insecure",
        affected_surfaces=["/missing"],
        evidence=[],
        impact_hypothesis="Unknown",
        attack_path="Guess",
        safe_reproduction=static_reproduction([], ""),
        confidence="low",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=[],
        retrieval_trace=[],
    )


def _generic_auth_gap_draft() -> AgentFindingDraft:
    context = RetrievedContext(
        id="c1",
        query_id="q1",
        source_type="file",
        excerpt="export function login() {}",
        score=0.8,
        reason="auth",
        source_path="src/auth.ts",
        context_category="auth",
    )
    evidence = evidence_from_context(context, "Auth-related production context supports access-control review")
    return AgentFindingDraft(
        id="draft-auth-generic",
        title="Potential auth boundary enforcement gap",
        vulnerability_class="broken-access-control",
        claim=(
            "Static evidence shows auth middleware or login route handlers that should enforce "
            "access control before sensitive API routes are reached."
        ),
        affected_surfaces=["/api/login", "Next.js frontend <-> FastAPI backend"],
        evidence=[evidence],
        impact_hypothesis="Missing auth checks.",
        attack_path="Review files.",
        safe_reproduction=static_reproduction(
            ["Inspect auth middleware and login route handler in identified files."],
            "Document routes lacking auth enforcement.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=[],
        retrieval_trace=["c1"],
    )


def test_verify_accepts_supported_draft():
    pack = _supported_pack()
    result = verify_draft(
        _supported_draft(),
        _scan_report(),
        context_paths={"src/auth.ts"},
        evidence_packs=[pack],
    )

    assert result.status == "verified"
    assert result.verified is not None
    assert result.verified.affected_files == ["src/auth.ts"]
    assert result.verified.affected_surfaces == ["/api/login"]
    assert "Next.js" not in result.verified.affected_files


def test_verify_rejects_unsupported_draft():
    result = verify_draft(_unsupported_draft(), _scan_report())

    assert result.status == "rejected"
    assert result.rejected is not None
    assert result.rejected.failed_checks
    assert "missing evidence refs" in result.rejected.failed_checks


def test_verify_rejects_generic_potential_auth_gap():
    result = verify_draft(
        _generic_auth_gap_draft(),
        _scan_report(),
        context_paths={"src/auth.ts"},
        evidence_packs=[],
    )

    assert result.status == "rejected"
    assert result.rejected is not None
    checks = " ".join(result.rejected.failed_checks).lower()
    assert "potential" in checks or "review-relevant" in checks or "not a route or repo file" in checks


def test_verify_rejects_review_only_evidence():
    draft = _supported_draft()
    weak = replace(
        draft.evidence[0],
        explanation="Auth-related production context supports access-control review",
        snippet=None,
        line_start=None,
        line_end=None,
    )
    result = verify_draft(
        replace(draft, evidence=[weak]),
        _scan_report(),
        context_paths={"src/auth.ts"},
        evidence_packs=[_supported_pack()],
    )

    assert result.status == "rejected"
    assert result.rejected is not None
    assert any("review" in check.lower() for check in result.rejected.failed_checks)


def test_verify_rejects_unredacted_secrets():
    draft = _supported_draft()
    leaked = replace(
        draft.evidence[0],
        snippet="API_KEY=live-secret-value-that-should-not-appear",
    )
    result = verify_draft(
        replace(draft, evidence=[leaked]),
        _scan_report(),
        context_paths={"src/auth.ts"},
        evidence_packs=[_supported_pack()],
    )

    assert result.status == "rejected"
    assert any("secret" in check.lower() for check in result.rejected.failed_checks)  # type: ignore[union-attr]


def test_specialist_auth_draft_is_rejected_without_concrete_evidence():
    hypothesis = AttackHypothesis(
        id="hyp-auth-1",
        agent_type="auth",
        specialist="auth-breaker",
        title="Auth boundary bypass",
        vulnerability_class="broken-access-control",
        target_surfaces=["/api/login"],
        target_files=["src/auth.ts"],
        reasoning="Auth files mapped",
        required_evidence=["auth middleware"],
        priority="high",
    )
    runtime_input = RuntimeInput(
        scan_report_path="scan.json",
        routed_skills_path="routed.json",
        repo=RepoIntelligence(
            version="0.1.0",
            scanned_at="2026-06-29T12:00:00.000Z",
            project_root="/tmp",
            inventory=InventoryResult(
                total_files=1,
                by_category={"typescript": 1},
                files=[FileInventoryItem(path="src/auth.ts", category="typescript")],
            ),
            surfaces=SurfacesResult(
                api=[SurfaceRoute(path="/api/login", file="src/auth.ts", framework="express")],
                auth=[SurfaceAuth(file="src/auth.ts", type="middleware")],
            ),
        ),
        routed_skills=RoutedSkills(report_path="scan.json", routed_at="2026-06-29T12:01:00.000Z"),
    )
    context = [
        RetrievedContext(
            id="c1",
            query_id="q1",
            source_type="file",
            excerpt="export function requireAuth() {}",
            score=0.8,
            reason="auth",
            source_path="src/auth.ts",
            context_category="auth",
        )
    ]
    draft = run_auth_breaker(hypothesis, runtime_input, context, evidence_packs=[])
    assert draft is None

    pack = EvidencePack(
        id="ep-auth",
        path="src/auth.ts",
        line_start=1,
        line_end=3,
        snippet="export function requireAuth() {}",
        symbol="requireAuth",
        surface_type="auth",
        kind="function",
    )
    draft_with_packs = run_auth_breaker(hypothesis, runtime_input, context, evidence_packs=[pack])
    if draft_with_packs is not None:
        result = verify_draft(
            draft_with_packs,
            _scan_report(),
            context_paths={"src/auth.ts"},
            evidence_packs=[pack],
        )
        assert result.status in {"verified", "rejected"}


def test_verify_drafts_batch():
    verified, rejected, needs = verify_drafts(
        [_supported_draft(), _unsupported_draft()],
        _scan_report(),
        context_paths={"src/auth.ts"},
        evidence_packs=[_supported_pack()],
    )

    assert len(verified) == 1
    assert len(rejected) == 1
    assert needs == []
