"""Tests for static specialist agents."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.agents.specialists.runner import run_specialists
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.models.agents import AttackHypothesis
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceAuth,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.redaction import redact_secrets


def _runtime_input(tmp_path: Path) -> RuntimeInput:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.ts").write_text("export function requireAuth() {}\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=super-secret-value\n", encoding="utf-8")

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=2,
            by_category={"typescript": 1, "config": 1},
            files=[
                FileInventoryItem(path="src/auth.ts", category="typescript"),
                FileInventoryItem(path=".env", category="config"),
            ],
        ),
        surfaces=SurfacesResult(
            api=[SurfaceRoute(path="/api/login", file="src/auth.ts", framework="express")],
            auth=[SurfaceAuth(file="src/auth.ts", type="middleware")],
        ),
    )
    return RuntimeInput(
        scan_report_path=tmp_path / "scan.json",
        routed_skills_path=tmp_path / "routed.json",
        repo=repo,
        routed_skills=RoutedSkills(
            report_path=str(tmp_path / "scan.json"),
            routed_at="2026-06-29T12:01:00.000Z",
            selected=[
                SelectedSkill(
                    name="testing-api-security-with-owasp-top-10",
                    path="skills/example/SKILL.md",
                    score=0.8,
                    reasons=["matched keyword: api"],
                    agent_types=["api", "auth", "secrets"],
                )
            ],
        ),
    )


def _hypotheses() -> list[AttackHypothesis]:
    return [
        AttackHypothesis(
            id="hyp-auth-1",
            agent_type="auth",
            specialist="auth-breaker",
            title="Auth boundary",
            vulnerability_class="broken-access-control",
            target_surfaces=["/api/login"],
            target_files=["src/auth.ts"],
            reasoning="auth",
            required_evidence=["auth middleware"],
            priority="high",
        ),
        AttackHypothesis(
            id="hyp-api-1",
            agent_type="api",
            specialist="api-abuse",
            title="API abuse",
            vulnerability_class="api-abuse",
            target_surfaces=["/api/login"],
            target_files=["src/auth.ts"],
            reasoning="api",
            required_evidence=["handler"],
            priority="high",
        ),
        AttackHypothesis(
            id="hyp-secrets-1",
            agent_type="secrets",
            specialist="secrets-config",
            title="Secrets",
            vulnerability_class="secret-exposure",
            target_surfaces=[],
            target_files=[".env"],
            reasoning="config",
            required_evidence=["config secret"],
            priority="high",
        ),
    ]


def test_specialists_emit_structured_drafts_and_redact_secrets(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
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
        ),
        RetrievedContext(
            id="c2",
            query_id="q1",
            source_type="file",
            excerpt="API_KEY=super-secret-value",
            score=0.9,
            reason="config",
            source_path=".env",
            context_category="config",
        ),
    ]

    drafts, rejected = run_specialists(
        runtime_input,
        _hypotheses(),
        context,
        build_evidence_packs(tmp_path, runtime_input.repo, {"src/auth.ts", ".env"}),
    )

    assert drafts
    secret_draft = next(item for item in drafts if item.specialist == "secrets-config")
    assert secret_draft.claim
    assert secret_draft.evidence
    assert secret_draft.safe_reproduction.mode == "static-proof"
    assert "super-secret-value" not in redact_secrets(secret_draft.evidence[0].snippet or "")


def test_specialists_reject_vague_findings_without_evidence(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
    vague_hypothesis = [
        AttackHypothesis(
            id="hyp-empty",
            agent_type="secrets",
            specialist="secrets-config",
            title="Secrets",
            vulnerability_class="secret-exposure",
            target_surfaces=[],
            target_files=["missing.env"],
            reasoning="none",
            required_evidence=["config secret"],
            priority="low",
        )
    ]

    drafts, rejected = run_specialists(runtime_input, vague_hypothesis, [], evidence_packs=[])

    assert not drafts
    assert rejected
