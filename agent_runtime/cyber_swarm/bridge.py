"""Deterministic JSON bridge from TypeScript scan artifacts to findings output."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.graph.workflow import run_workflow


def run_bridge(scan_report_path: Path, routed_skills_path: Path, output_path: Path) -> dict:
    return run_workflow(scan_report_path, routed_skills_path, output_path)
