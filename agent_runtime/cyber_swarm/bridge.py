"""Deterministic JSON bridge from TypeScript scan artifacts to findings output."""

from __future__ import annotations

import time
from pathlib import Path

from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.schemas.io import write_json
from cyber_swarm.schemas.report_md import write_markdown_report


def _print_summary(output: dict) -> None:
    metrics = output.get("metrics", {})
    activation = metrics.get("activation", {})
    verifier = metrics.get("verifier", {})
    ranking = metrics.get("risk_ranking", {})
    runtime = metrics.get("runtime", {})
    verified = output.get("verifiedFindings", [])
    rejected = output.get("rejectedFindings", [])
    needs = output.get("needsMoreEvidenceFindings", [])

    print("Cyber Swarm findings summary")
    if activation:
        print("  Activation (skills are supplemental, not the execution plan):")
        print(f"    skillsRouted: {activation.get('skillsRouted', 0)}")
        print(f"    agentsPlanned: {activation.get('agentsPlanned', 0)}")
        print(f"    agentsRun: {activation.get('agentsRun', 0)}")
        agent_types = activation.get("agentTypes", [])
        if isinstance(agent_types, list):
            print(
                f"    agentTypes: {', '.join(agent_types) if agent_types else 'none'}"
            )
        print(f"    findingsVerified: {activation.get('findingsVerified', len(verified))}")
        print(f"    findingsRejected: {activation.get('findingsRejected', len(rejected))}")
    print(f"  Verified: {len(verified)}")
    print(f"  Rejected: {len(rejected)}")
    print(f"  Needs evidence: {len(needs)}")
    if runtime:
        print(
            "  Runtime: "
            f"provider={runtime.get('provider', 'unknown')} "
            f"model={runtime.get('model', 'unknown')} "
            f"elapsedMs={runtime.get('elapsedMs', 'n/a')}"
        )
        calls = runtime.get("providerCalls", [])
        if isinstance(calls, list) and calls:
            total_tokens = sum(
                int(item.get("totalTokens") or 0)
                for item in calls
                if isinstance(item, dict)
            )
            print(f"  Model calls: {len(calls)}  Tokens: {total_tokens or 'n/a'}")
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


def run_bridge(
    scan_report_path: Path,
    routed_skills_path: Path,
    output_path: Path,
    *,
    runtime_config: RuntimeConfig | None = None,
) -> dict:
    started = time.perf_counter()
    output = run_workflow(
        scan_report_path,
        routed_skills_path,
        output_path,
        runtime_config=runtime_config,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    metrics = dict(output.get("metrics", {}))
    runtime = dict(metrics.get("runtime", {}))
    runtime["elapsedMs"] = elapsed_ms
    metrics["runtime"] = runtime
    output["metrics"] = metrics
    write_json(output_path, output)
    write_markdown_report(str(output_path), output)
    _print_summary(output)
    return output
