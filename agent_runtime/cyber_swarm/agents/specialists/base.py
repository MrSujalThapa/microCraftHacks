"""Shared helpers for static specialist agents."""

from __future__ import annotations

from cyber_swarm.agents.shared import (
    SECRET_PATTERN,
    file_contains_secret_pattern,
    skills_for_agent,
    static_reproduction,
)
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.models.agents import AgentFindingDraft, EvidenceRef
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.rag.redaction import redact_secrets


def production_context(context: list[RetrievedContext]) -> list[RetrievedContext]:
    return [
        item
        for item in context
        if item.source_path and (item.context_category != "test" or not item.is_supporting)
    ]


def context_for_paths(
    context: list[RetrievedContext],
    paths: list[str],
) -> list[RetrievedContext]:
    normalized_paths = {path.replace("\\", "/") for path in paths}
    return [
        item
        for item in production_context(context)
        if item.source_path and item.source_path.replace("\\", "/") in normalized_paths
    ]


def evidence_from_context(item: RetrievedContext, explanation: str) -> EvidenceRef:
    return EvidenceRef(
        type="skill" if item.source_type == "skill" else "file",
        path=item.source_path,
        route=item.source_path if item.context_category == "route" else None,
        line_start=item.line_start,
        line_end=item.line_end,
        snippet=redact_secrets(item.excerpt[:500]),
        explanation=explanation,
    )


def is_vague_draft(draft: AgentFindingDraft) -> tuple[bool, list[str]]:
    missing: list[str] = []
    if len(draft.claim.strip()) < 24:
        missing.append("claim too vague")
    if not draft.evidence:
        missing.append("missing evidence refs")
    file_evidence = [item for item in draft.evidence if item.type != "skill"]
    if file_evidence and not all(item.evidence_pack_id for item in file_evidence):
        missing.append("missing evidence pack refs")
    if file_evidence and not all(item.line_start is not None and item.path for item in file_evidence):
        missing.append("missing line-anchored file evidence")
    if not draft.affected_surfaces and not any(item.path for item in draft.evidence):
        missing.append("missing affected surface or file")
    if draft.confidence == "low" and not draft.evidence:
        missing.append("insufficient evidence for low-confidence claim")
    return (len(missing) > 0, missing)


__all__ = [
    "SECRET_PATTERN",
    "context_for_paths",
    "evidence_from_context",
    "evidence_from_pack",
    "file_contains_secret_pattern",
    "is_vague_draft",
    "production_context",
    "skills_for_agent",
    "static_reproduction",
]
