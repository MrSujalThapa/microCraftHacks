"""Deterministic JSON bridge from TypeScript scan artifacts to findings output."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cyber_swarm.schemas.io import load_json, write_json
from cyber_swarm.schemas.output import build_empty_output


def run_bridge(scan_report_path: Path, routed_skills_path: Path, output_path: Path) -> dict:
    started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    scan_report = load_json(scan_report_path)
    _routed_skills = load_json(routed_skills_path)

    output = build_empty_output(
        scan_report,
        scan_report_path,
        started_at=started_at,
        metrics={
            "bridge": "json",
            "routedSkillCount": len(_routed_skills.get("selected", [])),
        },
    )

    write_json(output_path, output)
    return output
