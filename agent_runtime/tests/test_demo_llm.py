"""Tests for focused demo LLM prompt, cache, and integration."""

from __future__ import annotations

import json
from pathlib import Path

from cyber_swarm.agents.demo_llm import parse_demo_findings_payload
from cyber_swarm.agents.demo_prompt import (
    _is_generic_route_validation_candidate,
    build_demo_llm_payload,
    select_top_graph_paths,
)
from cyber_swarm.agents.demo_llm import run_demo_findings_with_provider
from cyber_swarm.agents.shared import static_reproduction
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.attack_graph import AttackGraph, AttackGraphEdge, AttackGraphNode
from cyber_swarm.models.repo import InventoryResult, RepoIntelligence, SurfacesResult
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.providers.mock import MockProvider
from cyber_swarm.rag.redaction import contains_raw_secret
from cyber_swarm.schemas.cache import scan_content_hash


def _secret_pack() -> EvidencePack:
    return EvidencePack(
        id="pack-secret-1",
        path="backend/.env",
        line_start=4,
        line_end=4,
        snippet="SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>",
        symbol="SUPABASE_SERVICE_ROLE_KEY",
        surface_type="config",
        kind="env_assignment",
    )


def _generic_api_draft() -> AgentFindingDraft:
    pack = EvidencePack(
        id="pack-route-1",
        path="src/routes.py",
        line_start=10,
        line_end=12,
        snippet="@app.get('/api/health')",
        symbol="health",
        surface_type="api",
        kind="route_decorator",
        route="/api/health",
    )
    return AgentFindingDraft(
        id="draft-generic",
        title="/api/health handler lacks visible validation in src/routes.py",
        vulnerability_class="api-abuse",
        claim="Generic validation gap",
        affected_surfaces=["/api/health"],
        evidence=[evidence_from_pack(pack, "route handler")],
        impact_hypothesis="Abuse",
        attack_path="review route",
        safe_reproduction=static_reproduction(["Open file"], "Missing validation"),
        confidence="medium",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=[],
        retrieval_trace=[],
    )


def _runtime_input(tmp_path: Path) -> RuntimeInput:
    return RuntimeInput(
        scan_report_path=tmp_path / "scan.json",
        routed_skills_path=tmp_path / "routed.json",
        repo=RepoIntelligence(
            version="0.1.0",
            scanned_at="2026-01-01T00:00:00.000Z",
            project_root=str(tmp_path),
            inventory=InventoryResult(total_files=1, by_category={}, files=[]),
            surfaces=SurfacesResult(),
        ),
        routed_skills=RoutedSkills(report_path="", routed_at="", selected=[]),
    )


def test_prompt_builder_respects_caps():
    packs = [
        _secret_pack(),
        *[
            EvidencePack(
                id=f"pack-{index}",
                path=f"src/file{index}.py",
                line_start=index,
                line_end=index,
                snippet="code",
                symbol=None,
                surface_type="source",
                kind="function",
            )
            for index in range(2, 8)
        ],
    ]
    runtime_config = RuntimeConfig(mode="demo", latency="balanced")
    payload = build_demo_llm_payload(
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={
            "selected": [
                {"name": f"skill-{i}", "reasons": ["r"], "agentTypes": ["api"]} for i in range(5)
            ]
        },
        deterministic_candidates=[],
        runtime_config=runtime_config,
    )

    assert len(payload["evidencePacks"]) <= 3
    assert len(payload["playbookCards"]) <= 2
    assert payload["maxFindings"] == 2
    assert "SKILL.md" not in json.dumps(payload)


def test_generic_route_validation_candidate_filtered():
    assert _is_generic_route_validation_candidate(_generic_api_draft()) is True


def test_llm_output_without_pack_ids_rejected():
    parsed = parse_demo_findings_payload(
        {
            "findings": [
                {
                    "id": "bad",
                    "title": "Missing auth",
                    "vulnerability_class": "broken-access-control",
                    "claim": "No auth",
                    "agent_type": "auth",
                    "evidence_pack_ids": [],
                }
            ]
        },
        _runtime_input(Path("/tmp/demo")),
        [_secret_pack()],
        max_findings=2,
    )
    assert parsed == []


def test_demo_mode_makes_one_llm_call_with_mock(tmp_path: Path):
    scan_report_path = tmp_path / "scan-demo-llm.json"
    routed_skills_path = tmp_path / "routed-demo-llm.json"
    output_path = tmp_path / "scan-demo-llm-findings.json"
    env_path = tmp_path / "backend" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "SUPABASE_SERVICE_ROLE_KEY=super-secret-value-should-never-leak\n",
        encoding="utf-8",
    )

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {
                    "totalFiles": 1,
                    "byCategory": {"config": 1},
                    "files": [{"path": "backend/.env", "category": "config"}],
                },
                "surfaces": {"routes": [], "api": [], "auth": [], "dataModels": []},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [
                    {
                        "name": "secrets-skill",
                        "path": "skills/secrets/SKILL.md",
                        "score": 0.9,
                        "reasons": ["env file detected"],
                        "agentTypes": ["secrets"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    output = run_workflow(
        scan_report_path,
        routed_skills_path,
        output_path,
        runtime_config=RuntimeConfig(provider="mock", mode="demo"),
        scan_hash=scan_content_hash(scan_report_path),
    )

    calls = output["metrics"]["runtime"]["providerCalls"]
    assert len(calls) == 1
    assert calls[0]["purpose"] == "demo_findings"


def test_no_llm_skips_model_call(tmp_path: Path):
    scan_report_path = tmp_path / "scan-no-llm.json"
    routed_skills_path = tmp_path / "routed-no-llm.json"
    output_path = tmp_path / "scan-no-llm-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {"totalFiles": 0, "byCategory": {}, "files": []},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [],
            }
        ),
        encoding="utf-8",
    )

    output = run_workflow(
        scan_report_path,
        routed_skills_path,
        output_path,
        runtime_config=RuntimeConfig(provider="mock", mode="demo", no_llm=True),
        scan_hash=scan_content_hash(scan_report_path),
    )

    assert output["metrics"]["runtime"]["providerCalls"] == []


def test_llm_cache_hit_avoids_repeat_model_call(tmp_path: Path):
    provider = MockProvider()
    runtime_config = RuntimeConfig(provider="mock", mode="demo")
    pack = _secret_pack()
    routed = {
        "selected": [
            {
                "name": "secrets",
                "reasons": ["env"],
                "agentTypes": ["secrets"],
            }
        ]
    }
    runtime = _runtime_input(tmp_path)
    output_path = tmp_path / ".swarm" / "reports" / "findings.json"
    output_path.parent.mkdir(parents=True)
    scan_hash = "abc123"

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=[pack],
        attack_graph=None,
        routed_skills=routed,
        deterministic_candidates=[],
        runtime_config=runtime_config,
        scan_hash=scan_hash,
        output_path=str(output_path),
    )
    assert len(provider.call_log()) == 1

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=[pack],
        attack_graph=None,
        routed_skills=routed,
        deterministic_candidates=[],
        runtime_config=runtime_config,
        scan_hash=scan_hash,
        output_path=str(output_path),
    )
    assert len(provider.call_log()) == 1


def test_prompt_never_contains_raw_secrets():
    raw_pack = EvidencePack(
        id="pack-raw",
        path="backend/.env",
        line_start=1,
        line_end=1,
        snippet="API_KEY=live-secret-value-12345",
        symbol="API_KEY",
        surface_type="config",
        kind="env_assignment",
    )
    runtime_config = RuntimeConfig(mode="demo", latency="fastest")
    payload = build_demo_llm_payload(
        evidence_packs=[raw_pack],
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=[],
        runtime_config=runtime_config,
    )
    serialized = json.dumps(payload)
    assert "live-secret-value-12345" not in serialized
    assert contains_raw_secret(serialized) is False


def test_select_top_graph_paths_skips_public_health_route():
    graph = AttackGraph(
        nodes=[
            AttackGraphNode(
                id="route-health",
                node_type="handler",
                label="GET /api/health",
                path="src/main.py",
                line_start=1,
                route="/api/health",
            ),
            AttackGraphNode(
                id="missing-guard",
                node_type="auth_guard",
                label="missing guard",
                path="src/main.py",
                line_start=2,
            ),
        ],
        edges=[
            AttackGraphEdge(
                id="edge-health",
                source_id="route-health",
                target_id="missing-guard",
                edge_type="missing_guard",
                label="missing auth guard",
            )
        ],
    )
    paths = select_top_graph_paths(graph, max_paths=2)
    assert paths == []
