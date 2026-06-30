"""LangGraph node for building line-level evidence packs."""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cyber_swarm.evidence.prompt import format_packs_for_prompt
from cyber_swarm.evidence.secret_packs import is_secret_evidence_pack
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.graph.state import GraphState
from cyber_swarm.metrics.timing import merge_stage_timing
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.verifier.demo_quality import is_public_route


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
    started = time.perf_counter()
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before evidence pack build")

    project_root = Path(runtime_input.repo.project_root)
    context_paths = _context_paths(state)
    runtime_config = state.get("runtime_config")
    if not isinstance(runtime_config, RuntimeConfig):
        runtime_config = RuntimeConfig()

    max_packs = 48
    if runtime_config.is_demo:
        max_packs = 12

    packs = build_evidence_packs(
        project_root,
        runtime_input.repo,
        context_paths,
        max_packs=max_packs,
    )

    if runtime_config.is_demo:
        packs = [
            pack
            for pack in packs
            if not (pack.route and is_public_route(pack.route))
        ]
        secret_packs = [pack for pack in packs if is_secret_evidence_pack(pack)]
        other_packs = [pack for pack in packs if pack not in secret_packs]
        packs = (secret_packs + other_packs)[:max_packs]

    metrics = merge_stage_timing(
        dict(state.get("metrics", {})),
        "evidence_pack_build",
        round((time.perf_counter() - started) * 1000, 2),
    )

    return {
        **state,
        "evidence_packs": packs,
        "metrics": _merge_metrics(
            {**state, "metrics": metrics},
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
