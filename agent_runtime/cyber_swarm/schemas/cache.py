"""Scan report hashing and findings cache lookup."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


def scan_content_hash(scan_report_path: Path) -> str:
    digest = hashlib.sha256(scan_report_path.read_bytes()).hexdigest()
    return digest[:16]


def cache_metadata(output: dict[str, Any]) -> dict[str, Any]:
    cache = output.get("metrics", {}).get("cache", {})
    return cache if isinstance(cache, dict) else {}


def find_cached_findings(output_dir: Path, scan_hash: str) -> Path | None:
    if not output_dir.is_dir():
        return None

    candidates = sorted(output_dir.glob("*-findings.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cached_hash = cache_metadata(payload).get("scanHash")
        if cached_hash == scan_hash:
            return path
    return None


def copy_cached_findings(source: Path, destination: Path, *, scan_hash: str) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    metrics = dict(payload.get("metrics", {}))
    cache = dict(metrics.get("cache", {}))
    cache["scanHash"] = scan_hash
    cache["hit"] = True
    cache["sourcePath"] = str(source)
    metrics["cache"] = cache
    payload["metrics"] = metrics
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
