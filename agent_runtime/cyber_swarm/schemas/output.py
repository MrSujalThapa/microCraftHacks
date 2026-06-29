"""Build deterministic runtime output payloads."""

from __future__ import annotations

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
