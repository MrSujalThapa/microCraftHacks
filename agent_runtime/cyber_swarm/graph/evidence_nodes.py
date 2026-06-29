"""LangGraph node for building line-level evidence packs."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from cyber_swarm.evidence.prompt import format_packs_for_prompt
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.graph.state import GraphState


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def _context_paths(state: GraphState) -> set[str]:
    paths: set[str] = set()
    for item in state.get("selected_context", []):
        source_path = getattr(item, "source_path", None)
        if isinstance(source_path, str) and source_path:
            paths.add(source_path.replace("\\", "/"))
    return paths


def build_evidence_packs_node(state: GraphState) -> GraphState:
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before evidence pack build")

    project_root = Path(runtime_input.repo.project_root)
    context_paths = _context_paths(state)
    packs = build_evidence_packs(project_root, runtime_input.repo, context_paths)

    return {
        **state,
        "evidence_packs": packs,
        "metrics": _merge_metrics(
            state,
            "evidence_packs",
            {
                "status": "completed",
                "packCount": len(packs),
                "projectRoot": str(project_root),
                "contextPathCount": len(context_paths),
                "packSummary": format_packs_for_prompt(packs),
                "packs": [asdict(pack) for pack in packs[:32]],
            },
        ),
    }
