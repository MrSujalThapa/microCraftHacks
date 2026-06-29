"""LangGraph nodes for recon and attack planning agents."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.model_stages import (
    run_attack_planner_with_provider,
    run_recon_with_provider,
)
from cyber_swarm.agents.recon import run_recon
from cyber_swarm.agents.specialists.runner import run_specialists
from cyber_swarm.graph.state import GraphState
from cyber_swarm.models.runtime_config import RuntimeConfig


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


def recon_agent_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    selected_context = state.get("selected_context", [])
    runtime_config = _runtime_config(state)
    provider = state.get("provider")
    provider_metrics = _provider_metrics(state)

    if runtime_config.provider == "openai" and provider is not None:
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

    if runtime_config.provider == "openai" and provider is not None:
        hypotheses, stage_metrics = run_attack_planner_with_provider(
            provider,
            runtime_input,
            recon,
            selected_context,
            max_hypotheses=runtime_config.max_draft_findings,
        )
        provider_metrics["attack_planner"] = stage_metrics
    else:
        hypotheses = run_attack_planner(runtime_input, recon, selected_context)

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
    runtime_input = _get_runtime_input(state)
    hypotheses = state.get("attack_hypotheses", [])
    runtime_config = _runtime_config(state)
    from cyber_swarm.agents.specialists.runner import SPECIALISTS

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
        state.get("selected_context", []),
        state.get("evidence_packs", []),
    )
    drafts = drafts[: runtime_config.max_draft_findings]

    return {
        **state,
        "draft_findings": drafts,
        "rejected_findings": rejected,
        "metrics": _merge_metrics(
            state,
            "specialist_agents",
            {
                "status": "completed",
                "draftFindingCount": len(drafts),
                "rejectedDraftCount": len(rejected),
                "specialists": sorted({draft.specialist for draft in drafts}),
                "agentsRun": len(invoked_specialists),
                "invokedSpecialists": invoked_specialists,
                "maxDraftFindings": runtime_config.max_draft_findings,
            },
        ),
    }
