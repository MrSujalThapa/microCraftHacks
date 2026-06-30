"""Tests for focused demo LLM prompt, cache, merge, and integration."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cyber_swarm.agents.demo_llm import (
    DEMO_LLM_FALLBACK_MESSAGE,
    merge_confirmations,
    parse_demo_findings_payload,
    run_demo_findings_with_provider,
)
from cyber_swarm.agents.demo_prompt import (
    _is_generic_route_validation_candidate,
    build_demo_llm_payload,
    effective_max_confirmations,
    select_top_graph_paths,
)
from cyber_swarm.agents.shared import static_reproduction
from cyber_swarm.demo.diagnostics import format_rejection_diagnostics
from cyber_swarm.evidence.draft_helpers import build_deterministic_secret_drafts
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.attack_graph import AttackGraph, AttackGraphEdge, AttackGraphNode
from cyber_swarm.models.repo import FileInventoryItem, InventoryResult, RepoIntelligence, SurfacesResult
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.providers.mock import MockProvider, UnusableConfirmationMockProvider
from cyber_swarm.rag.redaction import contains_raw_secret
from cyber_swarm.schemas.cache import scan_content_hash
from cyber_swarm.schemas.llm_cache import llm_cache_key, normalized_scan_fingerprint, stable_evidence_hash
from cyber_swarm.verifier.verify import verify_draft


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


def _secret_runtime_input(tmp_path: Path) -> RuntimeInput:
    (tmp_path / "backend").mkdir(parents=True, exist_ok=True)
    (tmp_path / "backend" / ".env").write_text(
        "SUPABASE_SERVICE_ROLE_KEY=super-secret-service-role\n",
        encoding="utf-8",
    )
    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=1,
            by_category={"config": 1},
            files=[FileInventoryItem(path="backend/.env", category="config")],
        ),
        surfaces=SurfacesResult(),
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
                    name="secrets-config",
                    path="skills/example/SKILL.md",
                    score=0.9,
                    reasons=["config"],
                    agent_types=["secrets"],
                )
            ],
        ),
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


def _scan_report_for(tmp_path: Path) -> dict:
    return {
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
    assert payload["maxConfirmations"] == 1
    assert "SKILL.md" not in json.dumps(payload)


def test_balanced_mode_always_caps_to_one_confirmation():
    secret = AgentFindingDraft(
        id="draft-secret",
        title="Secret A",
        vulnerability_class="secret-exposure",
        claim="Secret A exposed",
        affected_surfaces=[],
        evidence=[evidence_from_pack(_secret_pack(), "Secret A exposed in backend/.env:4")],
        impact_hypothesis="Impact",
        attack_path="Inspect backend/.env",
        safe_reproduction=static_reproduction(["Open file"], "Secret visible"),
        confidence="high",
        agent_type="secrets",
        specialist="secrets-config",
        selected_skills=[],
        retrieval_trace=[],
    )
    bola = replace(
        secret,
        id="draft-bola",
        title="BOLA risk",
        vulnerability_class="bola",
        specialist="object-ownership",
    )
    assert effective_max_confirmations(
        RuntimeConfig(mode="demo", latency="balanced"),
        [secret, bola],
    ) == 1


def test_balanced_mode_caps_to_one_confirmation_by_default():
    candidates = [
        AgentFindingDraft(
            id="draft-1",
            title="Secret A",
            vulnerability_class="secret-exposure",
            claim="Secret A exposed",
            affected_surfaces=[],
            evidence=[evidence_from_pack(_secret_pack(), "Secret A exposed in backend/.env:4")],
            impact_hypothesis="Impact",
            attack_path="Inspect backend/.env",
            safe_reproduction=static_reproduction(["Open backend/.env"], "Secret visible"),
            confidence="high",
            agent_type="secrets",
            specialist="secrets-config",
            selected_skills=[],
            retrieval_trace=[],
        )
    ]
    assert effective_max_confirmations(RuntimeConfig(mode="demo", latency="balanced"), candidates) == 1


def test_generic_route_validation_candidate_filtered():
    assert _is_generic_route_validation_candidate(_generic_api_draft()) is True


def _manual_secret_draft() -> AgentFindingDraft:
    pack = _secret_pack()
    return AgentFindingDraft(
        id="draft-det-secret-1",
        title=f"Hardcoded {pack.symbol} in {pack.path}",
        vulnerability_class="secret-exposure",
        claim=(
            f"{pack.symbol} in {pack.path}:{pack.line_start} is assigned in tracked configuration "
            "without using a secret manager or runtime-only environment injection."
        ),
        affected_surfaces=[],
        evidence=[evidence_from_pack(pack, f"{pack.symbol} appears in {pack.path}:{pack.line_start}")],
        impact_hypothesis="Exposed secrets in tracked files can enable credential theft.",
        attack_path=f"Inspect {pack.path}:{pack.line_start}.",
        safe_reproduction=static_reproduction(
            [f"Open {pack.path}:{pack.line_start} and confirm redaction."],
            "Secret assignment visible in static configuration.",
        ),
        confidence="high",
        agent_type="secrets",
        specialist="secrets-config",
        selected_skills=[],
        retrieval_trace=[],
    )


def test_llm_output_without_candidate_id_rejected():
    secret_draft = _manual_secret_draft()
    parsed, issues = merge_confirmations(
        [secret_draft],
        {"confirmations": [{"confirmed": True, "candidateId": ""}]},
        runtime_config=RuntimeConfig(mode="demo", latency="balanced"),
    )
    assert parsed == []
    assert issues


def test_llm_output_with_invented_pack_ids_rejected():
    secret_draft = _manual_secret_draft()
    parsed, issues = merge_confirmations(
        [secret_draft],
        {
            "confirmations": [
                {
                    "candidateId": secret_draft.id,
                    "confirmed": True,
                    "evidence_pack_ids": ["pack-invented"],
                }
            ]
        },
        runtime_config=RuntimeConfig(mode="demo", latency="balanced"),
    )
    assert parsed == []
    assert any("evidence pack IDs" in issue for issue in issues)


def test_merged_deterministic_evidence_passes_verifier(tmp_path: Path):
    runtime_input = _secret_runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime_input.repo, {"backend/.env"})
    secret_draft = build_deterministic_secret_drafts(runtime_input, packs, [])[0]
    merged, _ = merge_confirmations(
        [secret_draft],
        {
            "confirmations": [
                {
                    "candidateId": secret_draft.id,
                    "confirmed": True,
                    "why_qa_misses_this": "Scanners skip env templates.",
                    "why_code_review_misses_this": "Reviewers assume examples are fake.",
                    "suggested_regression_test": "Fail CI on tracked credential assignments.",
                    "recommended_fix": "Move secret to runtime env injection.",
                }
            ]
        },
        runtime_config=RuntimeConfig(mode="demo", latency="balanced"),
    )
    assert len(merged) == 1
    result = verify_draft(merged[0], _scan_report_for(tmp_path), evidence_packs=packs)
    assert result.status == "verified"


def test_demo_mode_confirms_secret_and_verifies_end_to_end(tmp_path: Path):
    scan_report_path = tmp_path / "scan-demo-llm.json"
    routed_skills_path = tmp_path / "routed-demo-llm.json"
    output_path = tmp_path / "scan-demo-llm-findings.json"
    runtime_input = _secret_runtime_input(tmp_path)

    scan_report_path.write_text(json.dumps(_scan_report_for(tmp_path)), encoding="utf-8")
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
    assert len(output["verifiedFindings"]) >= 1
    assert output["verifiedFindings"][0]["vulnerability_class"] == "secret-exposure"


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
    runtime = _secret_runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime.repo, {"backend/.env"})
    drafts = build_deterministic_secret_drafts(runtime, packs, [])
    output_path = tmp_path / ".swarm" / "reports" / "findings.json"
    output_path.parent.mkdir(parents=True)
    fingerprint = normalized_scan_fingerprint(_scan_report_for(tmp_path))

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=runtime_config,
        content_fingerprint=fingerprint,
        output_path=str(output_path),
    )
    assert len(provider.call_log()) == 1

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=runtime_config,
        content_fingerprint=fingerprint,
        output_path=str(output_path),
    )
    assert len(provider.call_log()) == 1


def test_force_llm_bypasses_cache(tmp_path: Path):
    provider = MockProvider()
    runtime = _secret_runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime.repo, {"backend/.env"})
    drafts = build_deterministic_secret_drafts(runtime, packs, [])
    output_path = tmp_path / ".swarm" / "reports" / "findings.json"
    output_path.parent.mkdir(parents=True)
    fingerprint = normalized_scan_fingerprint(_scan_report_for(tmp_path))
    config = RuntimeConfig(provider="mock", mode="demo", force_llm=True)

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=config,
        content_fingerprint=fingerprint,
        output_path=str(output_path),
    )
    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=config,
        content_fingerprint=fingerprint,
        output_path=str(output_path),
    )
    assert len(provider.call_log()) == 2


def test_stable_llm_cache_key_ignores_scan_timestamp(tmp_path: Path):
    report_a = {
        "scannedAt": "2026-06-29T12:00:00.000Z",
        "inventory": {"files": [{"path": "backend/.env", "category": "config"}]},
        "surfaces": {"routes": [], "api": [], "auth": [], "dataModels": []},
    }
    report_b = {
        "scannedAt": "2026-06-30T02:00:00.000Z",
        "inventory": {"files": [{"path": "backend/.env", "category": "config"}]},
        "surfaces": {"routes": [], "api": [], "auth": [], "dataModels": []},
    }
    pack = _secret_pack()
    evidence_key = stable_evidence_hash([pack])
    key_a = llm_cache_key(
        content_fingerprint=normalized_scan_fingerprint(report_a),
        evidence_key=evidence_key,
        graph_key="graph",
        provider="openai",
        model="gpt-5-mini",
        latency_mode="balanced",
    )
    key_b = llm_cache_key(
        content_fingerprint=normalized_scan_fingerprint(report_b),
        evidence_key=evidence_key,
        graph_key="graph",
        provider="openai",
        model="gpt-5-mini",
        latency_mode="balanced",
    )
    assert key_a == key_b


def test_blank_llm_response_preserves_deterministic_verified_finding(tmp_path, monkeypatch):
    scan_report_path = tmp_path / "scan-blank-llm.json"
    routed_skills_path = tmp_path / "routed-blank-llm.json"
    output_path = tmp_path / "scan-blank-llm-findings.json"
    _secret_runtime_input(tmp_path)

    scan_report_path.write_text(json.dumps(_scan_report_for(tmp_path)), encoding="utf-8")
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

    monkeypatch.setattr(
        "cyber_swarm.graph.workflow.create_provider",
        lambda *_args, **_kwargs: UnusableConfirmationMockProvider(),
    )
    monkeypatch.setattr(
        "cyber_swarm.providers.factory.create_provider",
        lambda *_args, **_kwargs: UnusableConfirmationMockProvider(),
    )

    output = run_workflow(
        scan_report_path,
        routed_skills_path,
        output_path,
        runtime_config=RuntimeConfig(provider="mock", mode="demo", force_llm=True),
        scan_hash=scan_content_hash(scan_report_path),
    )

    demo_llm = output["metrics"]["runtime"]["demoLlm"]
    assert demo_llm["fallbackUsed"] is True
    assert demo_llm["fallbackMessage"] == DEMO_LLM_FALLBACK_MESSAGE
    assert demo_llm["confirmationsAccepted"] == 0
    assert demo_llm["providerCallsAttempted"] >= 1
    assert len(output["metrics"]["runtime"]["providerCalls"]) >= 1
    assert len(output["verifiedFindings"]) >= 1
    assert output["verifiedFindings"][0]["vulnerability_class"] == "secret-exposure"


def test_unusable_llm_response_reports_fallback_telemetry(tmp_path):
    provider = UnusableConfirmationMockProvider()
    runtime = _secret_runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime.repo, {"backend/.env"})
    drafts = build_deterministic_secret_drafts(runtime, packs, [])

    _drafts, stage = run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=RuntimeConfig(provider="mock", mode="demo", latency="balanced"),
        content_fingerprint=normalized_scan_fingerprint(_scan_report_for(tmp_path)),
    )

    assert stage["fallbackUsed"] is True
    assert stage["fallbackMessage"] == DEMO_LLM_FALLBACK_MESSAGE
    assert stage["confirmationsAccepted"] == 0
    assert stage["providerCallsAttempted"] >= 1


def test_output_token_cap_passed_to_provider(tmp_path: Path):
    provider = MockProvider()
    runtime = _secret_runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime.repo, {"backend/.env"})
    drafts = build_deterministic_secret_drafts(runtime, packs, [])

    run_demo_findings_with_provider(
        provider,
        runtime,
        evidence_packs=packs,
        attack_graph=None,
        routed_skills={"selected": []},
        deterministic_candidates=drafts,
        runtime_config=RuntimeConfig(provider="mock", mode="demo", latency="balanced"),
        content_fingerprint=normalized_scan_fingerprint(_scan_report_for(tmp_path)),
    )
    assert provider.call_log()[0]["maxOutputTokens"] == 600


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


def test_rejection_diagnostics_when_verified_zero():
    lines = format_rejection_diagnostics(
        {
            "verifiedFindings": [],
            "rejectedFindings": [
                {
                    "title": "Hardcoded API_KEY in backend/.env",
                    "vulnerability_class": "secret-exposure",
                    "reason": "claim does not match evidence",
                    "failed_checks": ["claim does not match evidence"],
                }
            ],
        }
    )
    assert len(lines) == 1
    assert "secret-exposure" in lines[0]


def test_parse_demo_findings_payload_legacy_empty_without_candidates(tmp_path: Path):
    parsed = parse_demo_findings_payload(
        {"confirmations": [{"candidateId": "missing", "confirmed": True}]},
        _secret_runtime_input(tmp_path),
        [_secret_pack()],
        max_findings=2,
        deterministic_candidates=[],
    )
    assert parsed == []
