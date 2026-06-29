"""Scan report hashing and findings cache lookup."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


class CacheReplayError(RuntimeError):
    """Raised when --from-cache is set but no matching cached run exists."""


CACHE_MISS_MESSAGE = (
    "No cached agent run for this scan hash. Run without --from-cache first."
)


def scan_content_hash(scan_report_path: Path) -> str:
    digest = hashlib.sha256(scan_report_path.read_bytes()).hexdigest()
    return digest[:16]


def cache_metadata(output: dict[str, Any]) -> dict[str, Any]:
    metrics = output.get("metrics", {})
    if not isinstance(metrics, dict):
        return {}

    runtime = metrics.get("runtime", {})
    if isinstance(runtime, dict):
        runtime_cache = runtime.get("cache", {})
        if isinstance(runtime_cache, dict) and runtime_cache:
            return runtime_cache

    top_level = metrics.get("cache", {})
    return top_level if isinstance(top_level, dict) else {}


def cache_runtime_metadata(output: dict[str, Any]) -> dict[str, Any]:
    metrics = output.get("metrics", {})
    if not isinstance(metrics, dict):
        return {}
    runtime = metrics.get("runtime", {})
    return runtime if isinstance(runtime, dict) else {}


def cache_entry_matches(
    payload: dict[str, Any],
    *,
    scan_hash: str,
    mode: str,
    provider: str,
    model: str,
) -> bool:
    cache = cache_metadata(payload)
    if cache.get("scanHash") != scan_hash:
        return False

    runtime = cache_runtime_metadata(payload)
    cached_mode = cache.get("mode") or runtime.get("mode")
    cached_provider = cache.get("provider") or runtime.get("provider")
    cached_model = cache.get("model") or runtime.get("model")

    if cached_mode and cached_mode != mode:
        return False
    if cached_provider and cached_provider != provider:
        return False
    if cached_model and cached_model != model:
        return False
    return True


def find_cached_findings(
    output_dir: Path,
    *,
    scan_hash: str,
    mode: str,
    provider: str,
    model: str,
) -> Path | None:
    if not output_dir.is_dir():
        return None

    candidates = sorted(
        output_dir.glob("*-findings.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if cache_entry_matches(
            payload,
            scan_hash=scan_hash,
            mode=mode,
            provider=provider,
            model=model,
        ):
            return path
    return None


def write_cache_metadata(
    metrics: dict[str, Any],
    *,
    scan_hash: str,
    hit: bool,
    mode: str,
    provider: str,
    model: str,
    source_path: str | None = None,
) -> dict[str, Any]:
    cache = {
        "scanHash": scan_hash,
        "hit": hit,
        "mode": mode,
        "provider": provider,
        "model": model,
    }
    if source_path:
        cache["sourcePath"] = source_path
    metrics["cache"] = cache
    runtime = dict(metrics.get("runtime", {}))
    runtime["cache"] = dict(cache)
    metrics["runtime"] = runtime
    return metrics


def copy_cached_findings(
    source: Path,
    destination: Path,
    *,
    scan_hash: str,
    mode: str,
    provider: str,
    model: str,
) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != destination.resolve():
        shutil.copy2(source, destination)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    metrics = dict(payload.get("metrics", {}))
    metrics = write_cache_metadata(
        metrics,
        scan_hash=scan_hash,
        hit=True,
        mode=mode,
        provider=provider,
        model=model,
        source_path=str(source),
    )
    runtime = dict(metrics.get("runtime", {}))
    runtime["elapsedMs"] = runtime.get("elapsedMs", 0)
    runtime["provider"] = provider
    runtime["model"] = model
    runtime["mode"] = mode
    runtime["providerCalls"] = []
    metrics["runtime"] = runtime
    payload["metrics"] = metrics
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
