"""LangGraph nodes for recon and attack planning agents."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.recon import run_recon
from cyber_swarm.agents.specialists.runner import run_specialists
from cyber_swarm.graph.state import GraphState


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def _get_runtime_input(state: GraphState):
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before agent nodes run")
    return runtime_input


def recon_agent_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    selected_context = state.get("selected_context", [])
    recon = run_recon(runtime_input, selected_context)

    return {
        **state,
        "recon_report": recon,
        "metrics": _merge_metrics(
            state,
            "recon_agent",
            {
                "status": "completed",
                "trustBoundaryCount": len(recon.trust_boundaries),
                "highRiskSurfaceCount": len(recon.high_risk_surfaces),
                "selectedAgentTargets": recon.selected_agent_targets,
            },
        ),
    }


def attack_planner_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    recon = state.get("recon_report")
    if recon is None:
        raise RuntimeError("recon_report is required before attack_planner runs")

    hypotheses = run_attack_planner(runtime_input, recon, state.get("selected_context", []))

    return {
        **state,
        "attack_hypotheses": hypotheses,
        "metrics": _merge_metrics(
            state,
            "attack_planner",
            {
                "status": "completed",
                "hypothesisCount": len(hypotheses),
                "hypotheses": [asdict(item) for item in hypotheses],
            },
        ),
    }


def specialist_agents_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    hypotheses = state.get("attack_hypotheses", [])
    drafts, rejected = run_specialists(
        runtime_input,
        hypotheses,
        state.get("selected_context", []),
    )

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
            },
        ),
    }
