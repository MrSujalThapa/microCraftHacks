"""Deterministic JSON bridge from TypeScript scan artifacts to findings output."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.graph.workflow import run_workflow


def _print_summary(output: dict) -> None:
    metrics = output.get("metrics", {})
    verifier = metrics.get("verifier", {})
    ranking = metrics.get("risk_ranking", {})
    verified = output.get("verifiedFindings", [])
    rejected = output.get("rejectedFindings", [])
    needs = output.get("needsMoreEvidenceFindings", [])

    print("Cyber Swarm findings summary")
    print(f"  Verified: {len(verified)}")
    print(f"  Rejected: {len(rejected)}")
    print(f"  Needs evidence: {len(needs)}")
    if verifier:
        print(
            "  Verifier: "
            f"reviewed={verifier.get('reviewedDraftCount', 0)} "
            f"verified={verifier.get('verifiedCount', 0)} "
            f"rejected={verifier.get('rejectedCount', 0)}"
        )
    severity_counts = ranking.get("severityCounts")
    if isinstance(severity_counts, dict):
        print(
            "  Severity: "
            + ", ".join(f"{key}={value}" for key, value in severity_counts.items() if value)
            or "none"
        )


def run_bridge(scan_report_path: Path, routed_skills_path: Path, output_path: Path) -> dict:
    output = run_workflow(scan_report_path, routed_skills_path, output_path)
    _print_summary(output)
    return output
