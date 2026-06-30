"""Tests for recon and attack planner agents."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.recon import run_recon
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
from cyber_swarm.models.skills import RoutedSkills


def _runtime_input(tmp_path: Path) -> RuntimeInput:
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
            selected=[],
        ),
    )


def test_recon_agent_identifies_trust_boundaries(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
    context = [
        RetrievedContext(
            id="1",
            query_id="q1",
            source_type="file",
            excerpt="export function requireAuth() {}",
            score=0.8,
            reason="auth",
            source_path="src/auth.ts",
            context_category="auth",
        )
    ]

    recon = run_recon(runtime_input, context)

    assert any(boundary.boundary_type == "auth" for boundary in recon.trust_boundaries)
    assert "auth" in recon.selected_agent_targets
    assert recon.high_risk_surfaces


def test_attack_planner_produces_structured_hypotheses(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
    context = [
        RetrievedContext(
            id="1",
            query_id="q1",
            source_type="file",
            excerpt="export function requireAuth() {}",
            score=0.8,
            reason="auth",
            source_path="src/auth.ts",
            context_category="auth",
        )
    ]
    recon = run_recon(runtime_input, context)
    hypotheses = run_attack_planner(runtime_input, recon, context)

    assert hypotheses
    first = hypotheses[0]
    assert first.id
    assert first.vulnerability_class
    assert first.target_files or first.target_surfaces
    assert first.required_evidence
    assert first.specialist in {
        "auth-boundary",
        "auth-breaker",
        "object-ownership",
        "api-abuse",
        "secrets-config",
        "storage-access",
        "ai-action-boundary",
    }
