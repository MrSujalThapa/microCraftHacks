"""LangGraph nodes for recon and attack planning agents."""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.demo_llm import run_demo_findings_with_provider
from cyber_swarm.agents.model_stages import (
    run_attack_planner_with_provider,
    run_recon_with_provider,
)
from cyber_swarm.agents.recon import run_recon
from cyber_swarm.agents.specialists.runner import run_specialists
from cyber_swarm.evidence.draft_helpers import build_deterministic_secret_drafts
from cyber_swarm.graph.state import GraphState
from cyber_swarm.metrics.timing import merge_stage_timing
from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.runtime_config import RuntimeConfig

_DEMO_SPECIALIST_PRIORITY = {
    "secrets-config": 0,
    "object-ownership": 1,
    "auth-boundary": 2,
    "auth-breaker": 2,
    "storage-access": 3,
    "ai-action-boundary": 4,
    "api-abuse": 5,
}


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def _get_runtime_input(state: GraphState):
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before agent nodes run")
    return runtime_input


def _runtime_config(state: GraphState) -> RuntimeConfig:
    config = state.get("runtime_config")
    if isinstance(config, RuntimeConfig):
        return config
    return RuntimeConfig()


def _provider_metrics(state: GraphState) -> dict[str, Any]:
    metrics = dict(state.get("provider_metrics", {}))
    return metrics


def _sort_hypotheses_for_demo(
    hypotheses: list,
    runtime_config: RuntimeConfig,
) -> list:
    if not runtime_config.is_demo:
        return hypotheses
    return sorted(
        hypotheses,
        key=lambda item: (_DEMO_SPECIALIST_PRIORITY.get(item.specialist, 99), item.id),
    )


def _prioritize_drafts_for_demo(
    drafts: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
) -> list[AgentFindingDraft]:
    if not runtime_config.is_demo:
        return drafts

    def sort_key(draft: AgentFindingDraft) -> tuple[int, str]:
        if draft.vulnerability_class == "secret-exposure":
            return (0, draft.id)
        if draft.specialist == "auth-breaker":
            return (1, draft.id)
        return (2, draft.id)

    return sorted(drafts, key=sort_key)


def _draft_file_key(draft: AgentFindingDraft) -> str:
    for item in draft.evidence:
        if item.path:
            return item.path
    return draft.id


def _merge_secret_drafts(
    deterministic: list[AgentFindingDraft],
    specialist_drafts: list[AgentFindingDraft],
) -> list[AgentFindingDraft]:
    merged: list[AgentFindingDraft] = []
    seen_files: set[str] = set()

    for draft in deterministic:
        file_key = _draft_file_key(draft)
        if file_key in seen_files:
            continue
        seen_files.add(file_key)
        merged.append(draft)

    for draft in specialist_drafts:
        if draft.vulnerability_class == "secret-exposure":
            file_key = _draft_file_key(draft)
            if file_key in seen_files:
                continue
            seen_files.add(file_key)
        merged.append(draft)

    return merged


def recon_agent_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    selected_context = state.get("selected_context", [])
    runtime_config = _runtime_config(state)
    provider = state.get("provider")
    provider_metrics = _provider_metrics(state)

    allow_model = (
        runtime_config.provider == "openai"
        and provider is not None
        and not runtime_config.is_demo
    )
    if allow_model:
        recon, stage_metrics = run_recon_with_provider(
            provider,
            runtime_input,
            selected_context,
        )
        provider_metrics["recon"] = stage_metrics
    else:
        recon = run_recon(runtime_input, selected_context)

    return {
        **state,
        "recon_report": recon,
        "provider_metrics": provider_metrics,
        "metrics": _merge_metrics(
            state,
            "recon_agent",
            {
                "status": "completed",
                "trustBoundaryCount": len(recon.trust_boundaries),
                "highRiskSurfaceCount": len(recon.high_risk_surfaces),
                "selectedAgentTargets": recon.selected_agent_targets,
                "provider": runtime_config.provider,
            },
        ),
    }


def attack_planner_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    recon = state.get("recon_report")
    if recon is None:
        raise RuntimeError("recon_report is required before attack_planner runs")

    runtime_config = _runtime_config(state)
    provider = state.get("provider")
    provider_metrics = _provider_metrics(state)
    selected_context = state.get("selected_context", [])
    max_hypotheses = runtime_config.effective_max_draft_findings()

    # Demo mode uses deterministic planning; the single LLM call happens in specialist_agents.
    allow_model = (
        runtime_config.provider == "openai"
        and provider is not None
        and not runtime_config.is_demo
    )

    if allow_model:
        hypotheses, stage_metrics = run_attack_planner_with_provider(
            provider,
            runtime_input,
            recon,
            selected_context,
            max_hypotheses=max_hypotheses,
        )
        provider_metrics["attack_planner"] = stage_metrics
    else:
        hypotheses = run_attack_planner(runtime_input, recon, selected_context)[:max_hypotheses]

    hypotheses = _sort_hypotheses_for_demo(hypotheses, runtime_config)

    return {
        **state,
        "attack_hypotheses": hypotheses,
        "provider_metrics": provider_metrics,
        "metrics": _merge_metrics(
            state,
            "attack_planner",
            {
                "status": "completed",
                "hypothesisCount": len(hypotheses),
                "hypotheses": [asdict(item) for item in hypotheses],
                "provider": runtime_config.provider,
            },
        ),
    }


def specialist_agents_node(state: GraphState) -> GraphState:
    started = time.perf_counter()
    runtime_input = _get_runtime_input(state)
    hypotheses = state.get("attack_hypotheses", [])
    runtime_config = _runtime_config(state)
    from cyber_swarm.agents.specialists.runner import SPECIALISTS

    evidence_packs = state.get("evidence_packs", [])
    selected_context = state.get("selected_context", [])
    provider = state.get("provider")
    provider_metrics = _provider_metrics(state)

    deterministic_secrets = build_deterministic_secret_drafts(
        runtime_input,
        evidence_packs,
        selected_context,
    )

    max_specialists = runtime_config.effective_max_specialists()
    hypotheses = _sort_hypotheses_for_demo(hypotheses, runtime_config)
    hypotheses = hypotheses[:max_specialists]

    invoked_specialists = sorted(
        {
            hypothesis.specialist
            for hypothesis in hypotheses
            if hypothesis.specialist in SPECIALISTS
        }
    )
    drafts, rejected = run_specialists(
        runtime_input,
        hypotheses,
        selected_context,
        evidence_packs,
        state.get("attack_graph"),
        demo=runtime_config.is_demo,
    )
    drafts = _merge_secret_drafts(deterministic_secrets, drafts)
    drafts = _prioritize_drafts_for_demo(drafts, runtime_config)

    deterministic_draft_ms = round((time.perf_counter() - started) * 1000, 2)
    metrics = dict(state.get("metrics", {}))
    metrics = merge_stage_timing(metrics, "deterministic_draft_generation", deterministic_draft_ms)

    llm_drafts: list[AgentFindingDraft] = []
    llm_stage: dict[str, Any] | None = None
    allow_demo_llm = (
        runtime_config.is_demo
        and runtime_config.llm_provider_enabled()
        and provider is not None
        and runtime_config.effective_max_model_calls() >= 1
    )

    if allow_demo_llm:
        llm_started = time.perf_counter()
        try:
            llm_drafts, llm_stage = run_demo_findings_with_provider(
                provider,
                runtime_input,
                evidence_packs=evidence_packs,
                attack_graph=state.get("attack_graph"),
                routed_skills=state.get("routed_skills", {}),
                deterministic_candidates=drafts,
                runtime_config=runtime_config,
                content_fingerprint=state.get("stable_content_fingerprint"),
                scan_report=state.get("scan_report", {}),
                output_path=state.get("output_path"),
            )
            provider_metrics["demo_findings"] = llm_stage
        except Exception as error:  # noqa: BLE001
            llm_stage = {"mode": "fallback", "error": str(error)}
            provider_metrics["demo_findings"] = llm_stage
            # Keep deterministic drafts when LLM fails; secrets remain verifier-eligible.
            llm_drafts = []
        metrics = merge_stage_timing(
            metrics,
            "llm_call",
            round((time.perf_counter() - llm_started) * 1000, 2),
        )
        if llm_stage and isinstance(llm_stage.get("llmCache"), dict):
            llm_cache = llm_stage["llmCache"]
            metrics["llmCache"] = llm_cache
            metrics = merge_stage_timing(
                metrics,
                "llm_prompt_build",
                float(llm_cache.get("promptBuildMs") or 0),
            )

    if llm_drafts:
        drafts = llm_drafts
    drafts = drafts[: runtime_config.effective_max_draft_findings()]

    return {
        **state,
        "draft_findings": drafts,
        "rejected_findings": rejected,
        "provider_metrics": provider_metrics,
        "metrics": _merge_metrics(
            {**state, "metrics": metrics},
            "specialist_agents",
            {
                "status": "completed",
                "draftFindingCount": len(drafts),
                "rejectedDraftCount": len(rejected),
                "deterministicSecretDraftCount": len(deterministic_secrets),
                "llmDraftCount": len(llm_drafts),
                "specialists": sorted({draft.specialist for draft in drafts}),
                "agentsRun": len(invoked_specialists),
                "invokedSpecialists": invoked_specialists,
                "maxDraftFindings": runtime_config.effective_max_draft_findings(),
                "maxSpecialists": max_specialists,
                "demoLlm": llm_stage,
            },
        ),
    }
