"""LangGraph nodes for finding verification, deduplication, and risk ranking."""

from __future__ import annotations

from typing import Any

from cyber_swarm.agents.model_stages import run_verifier_review_with_provider
from cyber_swarm.graph.state import GraphState
from cyber_swarm.models.agents import AgentFindingDraft, RejectedFindingDraft
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.verifier.dedup import dedupe_verified_findings
from cyber_swarm.verifier.demo_quality import annotate_demo_quality
from cyber_swarm.verifier.ranking import rank_verified_findings, severity_counts, _SEVERITY_ORDER
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
    runtime_config = state.get("runtime_config")
    if not isinstance(runtime_config, RuntimeConfig):
        runtime_config = RuntimeConfig()
    provider = state.get("provider")
    provider_metrics = dict(state.get("provider_metrics", {}))

    model_review: dict[str, Any] | None = None
    allow_verifier_model = (
        runtime_config.provider == "openai"
        and provider is not None
        and not runtime_config.is_demo
    )
    if allow_verifier_model:
        model_review = run_verifier_review_with_provider(
            provider,
            drafts,
            scan_report,
            max_drafts=runtime_config.effective_max_draft_findings(),
        )
        provider_metrics["verifier"] = model_review

    verified, verifier_rejected, needs_evidence = verify_drafts(
        drafts,
        scan_report,
        context_paths=context_paths,
        evidence_packs=state.get("evidence_packs", []),
    )

    agent_rejected = [
        item
        for item in state.get("rejected_findings", [])
        if isinstance(item, RejectedFindingDraft)
    ]

    verifier_metrics: dict[str, Any] = {
        "status": "completed",
        "reviewedDraftCount": len(drafts),
        "verifiedCount": len(verified),
        "rejectedCount": len(verifier_rejected),
        "needsEvidenceCount": len(needs_evidence),
        "agentRejectedCount": len(agent_rejected),
        "provider": runtime_config.provider,
    }
    if model_review is not None:
        verifier_metrics["modelReview"] = model_review.get("review")
        verifier_metrics["modelReviewMode"] = model_review.get("mode")

    return {
        **state,
        "verified_findings": verified,
        "verifier_rejected_findings": verifier_rejected,
        "needs_evidence_findings": needs_evidence,
        "rejected_findings": agent_rejected,
        "provider_metrics": provider_metrics,
        "metrics": _merge_metrics(
            state,
            "verifier",
            verifier_metrics,
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
    annotated = [annotate_demo_quality(item) for item in ranked]
    annotated.sort(
        key=lambda item: (
            0 if item.demo_ready else 1,
            -_SEVERITY_ORDER[item.severity],
            -item.ranking_rationale.total_score,
            item.title,
        )
    )
    counts = severity_counts(annotated)
    demo_ready_count = sum(1 for item in annotated if item.demo_ready)

    return {
        **state,
        "verified_findings": annotated,
        "metrics": _merge_metrics(
            state,
            "risk_ranking",
            {
                "status": "completed",
                "findingCount": len(annotated),
                "severityCounts": counts,
                "demoReadyCount": demo_ready_count,
            },
        ),
    }
