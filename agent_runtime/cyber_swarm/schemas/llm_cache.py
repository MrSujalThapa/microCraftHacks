"""Model-result cache for demo LLM responses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cyber_swarm.agents.demo_prompt import DEMO_PROMPT_VERSION
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.attack_graph import AttackGraph


def _digest(parts: list[str]) -> str:
    joined = "|".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def evidence_hash(packs: list[EvidencePack]) -> str:
    parts: list[str] = []
    for pack in sorted(packs, key=lambda item: item.id):
        parts.append(
            f"{pack.id}:{pack.path}:{pack.line_start}:{pack.line_end}:{pack.surface_type}"
        )
    return _digest(parts)


def graph_hash(graph: AttackGraph | None, path_ids: list[str]) -> str:
    if graph is None:
        return _digest([])
    parts = [f"{path_id}" for path_id in sorted(path_ids)]
    for node in sorted(graph.nodes, key=lambda item: item.id):
        parts.append(f"n:{node.id}:{node.node_type}:{node.path}:{node.line_start}")
    return _digest(parts)


def llm_cache_key(
    *,
    scan_hash: str,
    evidence_key: str,
    graph_key: str,
    provider: str,
    model: str,
    latency_mode: str,
    prompt_version: str = DEMO_PROMPT_VERSION,
) -> str:
    return _digest(
        [
            scan_hash,
            evidence_key,
            graph_key,
            prompt_version,
            provider,
            model,
            latency_mode,
        ]
    )


def llm_cache_dir(output_path: Path) -> Path:
    # .swarm/reports/foo-findings.json -> .swarm/cache/llm-results
    swarm_root = output_path.parent.parent
    return swarm_root / "cache" / "llm-results"


def llm_cache_path(output_path: Path, cache_key: str) -> Path:
    return llm_cache_dir(output_path) / f"{cache_key}.json"


def read_llm_cache(cache_path: Path) -> dict[str, Any] | None:
    if not cache_path.is_file():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def write_llm_cache(
    cache_path: Path,
    *,
    cache_key: str,
    scan_hash: str,
    evidence_key: str,
    graph_key: str,
    provider: str,
    model: str,
    latency_mode: str,
    llm_payload: dict[str, Any],
    call_meta: dict[str, Any],
) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cacheKey": cache_key,
        "scanHash": scan_hash,
        "evidenceHash": evidence_key,
        "graphHash": graph_key,
        "promptVersion": DEMO_PROMPT_VERSION,
        "provider": provider,
        "model": model,
        "latencyMode": latency_mode,
        "llmPayload": llm_payload,
        "call": call_meta,
    }
    cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
