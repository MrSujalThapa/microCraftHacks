"""LangGraph nodes for finding verification, deduplication, and risk ranking."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cyber_swarm.graph.state import GraphState
from cyber_swarm.models.agents import AgentFindingDraft, RejectedFindingDraft
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


def _serialize_agent_rejection(item: RejectedFindingDraft) -> dict[str, Any]:
    payload = asdict(item)
    payload["source"] = "agent"
    return payload


def _serialize_verifier_rejection(item) -> dict[str, Any]:
    return asdict(item)


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
