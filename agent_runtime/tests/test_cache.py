"""Tests for findings cache replay."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cyber_swarm.bridge import run_bridge
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.schemas.cache import (
    CACHE_MISS_MESSAGE,
    CacheReplayError,
    scan_content_hash,
    write_cache_metadata,
)


def _write_scan_and_routed(tmp_path: Path) -> tuple[Path, Path]:
    scan_report_path = tmp_path / "scan-cache.json"
    routed_skills_path = tmp_path / "routed-cache.json"
    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {"totalFiles": 0, "byCategory": {}, "files": []},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [],
            }
        ),
        encoding="utf-8",
    )
    return scan_report_path, routed_skills_path


def _cached_findings_payload(scan_hash: str) -> dict:
    metrics = write_cache_metadata(
        {
            "runtime": {
                "provider": "mock",
                "model": "gpt-5-mini",
                "mode": "full",
                "providerCalls": [{"stage": "recon", "totalTokens": 42}],
            }
        },
        scan_hash=scan_hash,
        hit=False,
        mode="full",
        provider="mock",
        model="gpt-5-mini",
    )
    return {
        "version": 1,
        "scanId": "2026-06-29T12-00-00-000Z",
        "status": "completed",
        "verifiedFindings": [{"id": "verified-draft-h1", "title": "Cached secret"}],
        "rejectedFindings": [],
        "metrics": metrics,
    }


def test_from_cache_miss_fails_fast_without_workflow(tmp_path: Path):
    scan_report_path, routed_skills_path = _write_scan_and_routed(tmp_path)
    output_path = tmp_path / "scan-cache-findings.json"

    with patch("cyber_swarm.bridge.run_workflow") as workflow:
        with pytest.raises(CacheReplayError, match=CACHE_MISS_MESSAGE):
            run_bridge(
                scan_report_path,
                routed_skills_path,
                output_path,
                runtime_config=RuntimeConfig(from_cache=True, provider="mock"),
            )
        workflow.assert_not_called()


def test_from_cache_hit_replays_without_model_calls(tmp_path: Path):
    scan_report_path, routed_skills_path = _write_scan_and_routed(tmp_path)
    output_path = tmp_path / "scan-cache-findings.json"
    scan_hash = scan_content_hash(scan_report_path)

    cached_path = tmp_path / "prior-scan-findings.json"
    cached_path.write_text(json.dumps(_cached_findings_payload(scan_hash), indent=2), encoding="utf-8")

    with patch("cyber_swarm.bridge.run_workflow") as workflow:
        output = run_bridge(
            scan_report_path,
            routed_skills_path,
            output_path,
            runtime_config=RuntimeConfig(from_cache=True, provider="mock", mode="full"),
        )
        workflow.assert_not_called()

    runtime = output["metrics"]["runtime"]
    assert runtime["cache"]["hit"] is True
    assert runtime["providerCalls"] == []
    assert output_path.exists()
