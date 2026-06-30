"""Build deterministic runtime output payloads."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def derive_scan_id(scan_report: dict[str, Any], scan_report_path: Path) -> str:
    scan_id = scan_report.get("scanId")
    if isinstance(scan_id, str) and scan_id:
        return scan_id

    scanned_at = scan_report.get("scannedAt")
    if isinstance(scanned_at, str) and scanned_at:
        return scanned_at.replace(":", "-").replace(".", "-")

    return scan_report_path.stem


def build_output(
    scan_report: dict[str, Any],
    scan_report_path: Path,
    *,
    started_at: str | None = None,
    completed_at: str | None = None,
    metrics: dict[str, Any] | None = None,
    verified_findings: list[Any] | None = None,
    rejected_findings: list[Any] | None = None,
    needs_evidence_findings: list[Any] | None = None,
) -> dict[str, Any]:
    started = started_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    completed = completed_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")

    verified = verified_findings or []
    rejected = rejected_findings or []
    needs_evidence = needs_evidence_findings or []

    return {
        "version": 1,
        "scanId": derive_scan_id(scan_report, scan_report_path),
        "status": "completed",
        "startedAt": started,
        "completedAt": completed,
        "metrics": metrics or {},
        "verifiedFindings": [
            asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in verified
        ],
        "rejectedFindings": [
            asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in rejected
        ],
        "needsMoreEvidenceFindings": [
            asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in needs_evidence
        ],
        "capabilityDrafts": [],
        "errors": [],
    }


def build_empty_output(
    scan_report: dict[str, Any],
    scan_report_path: Path,
    *,
    started_at: str | None = None,
    completed_at: str | None = None,
    metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = started_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    completed = completed_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")

    return {
        "version": 1,
        "scanId": derive_scan_id(scan_report, scan_report_path),
        "status": "completed",
        "startedAt": started,
        "completedAt": completed,
        "metrics": metrics or {},
        "verifiedFindings": [],
        "rejectedFindings": [],
        "capabilityDrafts": [],
        "errors": [],
    }
