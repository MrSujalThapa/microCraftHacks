"""LangGraph node for building the static attack graph."""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.graph.attack_graph_builder import build_attack_graph
from cyber_swarm.graph.state import GraphState
from cyber_swarm.metrics.timing import merge_stage_timing


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def build_attack_graph_node(state: GraphState) -> GraphState:
    started = time.perf_counter()
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before build_attack_graph runs")

    evidence_packs = state.get("evidence_packs", [])
    pack_lookup: dict[tuple[str, int], str] = {}
    for pack in evidence_packs:
        if isinstance(pack, EvidencePack):
            pack_lookup[(pack.path.replace("\\", "/"), pack.line_start)] = pack.id

    context_paths = {
        item.source_path.replace("\\", "/")
        for item in state.get("selected_context", [])
        if item.source_path
    }

    attack_graph = build_attack_graph(
        Path(runtime_input.repo.project_root),
        runtime_input.repo,
        context_paths,
        pack_id_by_location=pack_lookup,
    )

    metrics = merge_stage_timing(
        dict(state.get("metrics", {})),
        "attack_graph_build",
        round((time.perf_counter() - started) * 1000, 2),
    )

    return {
        **state,
        "attack_graph": attack_graph,
        "metrics": _merge_metrics(
            {**state, "metrics": metrics},
            "attack_graph",
            {
                "status": "completed",
                "nodeCount": len(attack_graph.nodes),
                "edgeCount": len(attack_graph.edges),
            },
        ),
    }


def attack_graph_to_dict(attack_graph) -> dict[str, Any]:
    return {
        "nodes": [asdict(node) for node in attack_graph.nodes],
        "edges": [asdict(edge) for edge in attack_graph.edges],
    }
