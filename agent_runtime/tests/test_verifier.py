"""Tests for draft finding verification."""

from __future__ import annotations

from cyber_swarm.agents.specialists.base import evidence_from_context, static_reproduction
from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.retrieval import RetrievedContext
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


def _supported_draft() -> AgentFindingDraft:
    context = RetrievedContext(
        id="c1",
        query_id="q1",
        source_type="file",
        excerpt="export function requireAuth() {}",
        score=0.8,
        reason="auth",
        source_path="src/auth.ts",
        context_category="auth",
    )
    evidence = evidence_from_context(context, "Auth middleware enforces access control on login route")
    return AgentFindingDraft(
        id="draft-auth-supported",
        title="Auth boundary gap",
        vulnerability_class="broken-access-control",
        claim=(
            "Static auth middleware evidence on login route handlers should enforce access control "
            "before sensitive API routes are reached."
        ),
        affected_surfaces=["/api/login"],
        evidence=[evidence],
        impact_hypothesis="Unauthorized API access if auth checks are missing.",
        attack_path="Review auth middleware coverage for protected routes.",
        safe_reproduction=static_reproduction(
            ["Inspect auth middleware in src/auth.ts without live requests."],
            "Document routes lacking auth enforcement.",
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


def test_verify_accepts_supported_draft():
    result = verify_draft(_supported_draft(), _scan_report(), context_paths={"src/auth.ts"})

    assert result.status == "verified"
    assert result.verified is not None
    assert result.verified.source_draft_ids == ["draft-auth-supported"]
    assert "/api/login" in result.verified.affected_surfaces


def test_verify_rejects_unsupported_draft():
    result = verify_draft(_unsupported_draft(), _scan_report())

    assert result.status == "rejected"
    assert result.rejected is not None
    assert result.rejected.failed_checks
    assert "missing evidence refs" in result.rejected.failed_checks


def test_verify_rejects_unredacted_secrets():
    draft = _supported_draft()
    bad_evidence = draft.evidence[0]
    from dataclasses import replace

    from cyber_swarm.models.agents import EvidenceRef

    leaked = replace(
        bad_evidence,
        snippet="API_KEY=live-secret-value-that-should-not-appear",
    )
    leaked_draft = replace(draft, evidence=[leaked])

    result = verify_draft(leaked_draft, _scan_report(), context_paths={"src/auth.ts"})

    assert result.status == "rejected"
    assert any("secret" in check.lower() for check in result.rejected.failed_checks)  # type: ignore[union-attr]


def test_verify_drafts_batch():
    verified, rejected, needs = verify_drafts(
        [_supported_draft(), _unsupported_draft()],
        _scan_report(),
        context_paths={"src/auth.ts"},
    )

    assert len(verified) == 1
    assert len(rejected) == 1
    assert needs == []
