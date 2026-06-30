"""Model-result cache for demo LLM responses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cyber_swarm.agents.demo_prompt import DEMO_PROMPT_VERSION
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.rag.redaction import redact_secrets


def _digest(parts: list[str]) -> str:
    joined = "|".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def normalized_scan_fingerprint(scan_report: dict[str, Any]) -> str:
    """Stable fingerprint excluding timestamps, paths, and run identifiers."""
    inventory = scan_report.get("inventory", {})
    files = inventory.get("files", []) if isinstance(inventory, dict) else []
    file_parts = sorted(
        f"{item.get('path')}:{item.get('category', '')}"
        for item in files
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    )

    surfaces = scan_report.get("surfaces", {})
    surface_parts: list[str] = []
    if isinstance(surfaces, dict):
        for key in ("routes", "api", "auth", "dataModels"):
            items = surfaces.get(key, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                if key in {"routes", "api"}:
                    surface_parts.append(f"{key}:{item.get('path')}:{item.get('file')}")
                else:
                    surface_parts.append(f"{key}:{item.get('file')}:{item.get('name') or item.get('type')}")

    stack = scan_report.get("stack", [])
    stack_parts = sorted(
        f"{item.get('name')}:{item.get('confidence')}"
        for item in stack
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )

    return _digest([*file_parts, *sorted(surface_parts), *stack_parts])


def stable_evidence_hash(packs: list[EvidencePack]) -> str:
    parts: list[str] = []
    for pack in sorted(packs, key=lambda item: item.id):
        snippet = redact_secrets(pack.snippet).replace("\n", " ").strip()
        parts.append(
            f"{pack.id}:{pack.path}:{pack.line_start}:{pack.line_end}:{snippet}:{pack.surface_type}"
        )
    return _digest(parts)


def stable_graph_hash(graph: AttackGraph | None, path_ids: list[str]) -> str:
    if graph is None:
        return _digest([])
    parts = [f"path:{path_id}" for path_id in sorted(path_ids)]
    for edge in sorted(graph.edges, key=lambda item: item.id):
        parts.append(f"e:{edge.id}:{edge.edge_type}:{edge.source_id}:{edge.target_id}:{edge.label}")
    return _digest(parts)


def llm_cache_key(
    *,
    content_fingerprint: str,
    evidence_key: str,
    graph_key: str,
    provider: str,
    model: str,
    latency_mode: str,
    prompt_version: str = DEMO_PROMPT_VERSION,
) -> str:
    return _digest(
        [
            content_fingerprint,
            evidence_key,
            graph_key,
            prompt_version,
            provider,
            model,
            latency_mode,
        ]
    )


def llm_cache_dir(output_path: Path) -> Path:
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
    content_fingerprint: str,
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
        "contentFingerprint": content_fingerprint,
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


# Backward-compatible aliases used in tests
evidence_hash = stable_evidence_hash
graph_hash = stable_graph_hash
