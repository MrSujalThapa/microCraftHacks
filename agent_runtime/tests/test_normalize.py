"""Tests for runtime input normalization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyber_swarm.models import RuntimeInputError
from cyber_swarm.rag.normalize import normalize_runtime_input, normalize_scan_report


def _minimal_scan_report() -> dict:
    return {
        "version": "0.1.0",
        "scannedAt": "2026-06-29T12:00:00.000Z",
        "projectRoot": "/tmp/project",
        "inventory": {
            "totalFiles": 2,
            "byCategory": {"typescript": 2},
            "files": [
                {"path": "src/cli/index.ts", "category": "typescript"},
                {"path": "package.json", "category": "config"},
            ],
        },
        "stack": [{"name": "Express", "confidence": "high", "evidence": ["package.json"]}],
        "surfaces": {
            "routes": [{"path": "/health", "file": "src/server.ts", "framework": "express"}],
            "api": [],
            "auth": [{"file": "src/auth.ts", "type": "middleware"}],
            "dataModels": [],
        },
    }


def _minimal_routed_skills() -> dict:
    return {
        "reportPath": "/tmp/project/.swarm/reports/scan.json",
        "routedAt": "2026-06-29T12:01:00.000Z",
        "selected": [
            {
                "name": "testing-api-security-with-owasp-top-10",
                "path": "skills/external/example/SKILL.md",
                "score": 0.7,
                "reasons": ["matched keyword: api"],
                "agentTypes": ["api"],
            }
        ],
    }


def test_normalize_scan_report_accepts_valid_payload():
    repo = normalize_scan_report(_minimal_scan_report())

    assert repo.scanned_at == "2026-06-29T12:00:00.000Z"
    assert repo.inventory.total_files == 2
    assert repo.stack[0].name == "Express"
    assert repo.surfaces.routes[0].path == "/health"


def test_normalize_scan_report_rejects_missing_inventory(tmp_path: Path):
    payload = _minimal_scan_report()
    del payload["inventory"]

    with pytest.raises(RuntimeInputError, match="inventory must be an object"):
        normalize_scan_report(payload)


def test_normalize_runtime_input_loads_artifacts(tmp_path: Path):
    scan_report_path = tmp_path / "scan.json"
    routed_skills_path = tmp_path / "routed-skills.json"
    scan_report_path.write_text(json.dumps(_minimal_scan_report()), encoding="utf-8")
    routed_skills_path.write_text(json.dumps(_minimal_routed_skills()), encoding="utf-8")

    runtime_input = normalize_runtime_input(scan_report_path, routed_skills_path)

    assert isinstance(runtime_input.repo.project_root, str)
    assert runtime_input.routed_skills.selected[0].name.startswith("testing-api")


def test_normalize_runtime_input_rejects_invalid_routed_skills(tmp_path: Path):
    scan_report_path = tmp_path / "scan.json"
    routed_skills_path = tmp_path / "routed-skills.json"
    scan_report_path.write_text(json.dumps(_minimal_scan_report()), encoding="utf-8")
    routed_skills_path.write_text(json.dumps({"selected": "not-an-array"}), encoding="utf-8")

    with pytest.raises(RuntimeInputError, match="selected must be an array"):
        normalize_runtime_input(scan_report_path, routed_skills_path)
