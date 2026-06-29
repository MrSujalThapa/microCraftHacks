"""LangGraph nodes for finding verification, deduplication, and risk ranking."""

from __future__ import annotations

from typing import Any

from cyber_swarm.graph.state import GraphState
from cyber_swarm.models.agents import AgentFindingDraft, RejectedFindingDraft
from cyber_swarm.verifier.dedup import dedupe_verified_findings
from cyber_swarm.verifier.ranking import rank_verified_findings, severity_counts
from cyber_swarm.verifier.verify import verify_drafts


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def _context_paths_from_state(state: GraphState) -> set[str]:
    paths: set[str] = set()
    for item in state.get("selected_context", []):
        source_path = getattr(item, "source_path", None)
        if isinstance(source_path, str) and source_path:
            paths.add(source_path)
    return paths


def verifier_node(state: GraphState) -> GraphState:
    scan_report = state.get("scan_report", {})
    drafts = [
        item
        for item in state.get("draft_findings", [])
        if isinstance(item, AgentFindingDraft)
    ]
    context_paths = _context_paths_from_state(state)

    verified, verifier_rejected, needs_evidence = verify_drafts(
        drafts,
        scan_report,
        context_paths=context_paths,
    )

    agent_rejected = [
        item
        for item in state.get("rejected_findings", [])
        if isinstance(item, RejectedFindingDraft)
    ]

    return {
        **state,
        "verified_findings": verified,
        "verifier_rejected_findings": verifier_rejected,
        "needs_evidence_findings": needs_evidence,
        "rejected_findings": agent_rejected,
        "metrics": _merge_metrics(
            state,
            "verifier",
            {
                "status": "completed",
                "reviewedDraftCount": len(drafts),
                "verifiedCount": len(verified),
                "rejectedCount": len(verifier_rejected),
                "needsEvidenceCount": len(needs_evidence),
                "agentRejectedCount": len(agent_rejected),
            },
        ),
    }


def dedup_node(state: GraphState) -> GraphState:
    verified = [
        item
        for item in state.get("verified_findings", [])
        if hasattr(item, "vulnerability_class")
    ]
    deduped, merged_count = dedupe_verified_findings(verified)

    return {
        **state,
        "verified_findings": deduped,
        "metrics": _merge_metrics(
            state,
            "dedup",
            {
                "status": "completed",
                "inputCount": len(verified),
                "outputCount": len(deduped),
                "mergedCount": merged_count,
            },
        ),
    }


def rank_node(state: GraphState) -> GraphState:
    verified = [
        item
        for item in state.get("verified_findings", [])
        if hasattr(item, "vulnerability_class")
    ]
    ranked = rank_verified_findings(verified)
    counts = severity_counts(ranked)

    return {
        **state,
        "verified_findings": ranked,
        "metrics": _merge_metrics(
            state,
            "risk_ranking",
            {
                "status": "completed",
                "findingCount": len(ranked),
                "severityCounts": counts,
            },
        ),
    }
