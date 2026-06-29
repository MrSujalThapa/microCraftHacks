"""Shared helpers for static specialist agents."""

from __future__ import annotations

import re

from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis, EvidenceRef, SafeReproduction
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.rag.redaction import redact_secrets

SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*\S+"
)


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


def skills_for_agent(runtime_input: RuntimeInput, agent_type: str) -> list[str]:
    return [
        skill.name
        for skill in runtime_input.routed_skills.selected
        if agent_type in skill.agent_types
    ][:3]


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


def static_reproduction(steps: list[str], expected: str) -> SafeReproduction:
    return SafeReproduction(
        mode="static-proof",
        steps=steps,
        expected_result=expected,
        safety_notes=[
            "Static analysis only; no runtime probing or destructive actions.",
            "Review redacted excerpts locally before any active testing.",
        ],
    )


def is_vague_draft(draft: AgentFindingDraft) -> tuple[bool, list[str]]:
    missing: list[str] = []
    if len(draft.claim.strip()) < 24:
        missing.append("claim too vague")
    if not draft.evidence:
        missing.append("missing evidence refs")
    if not draft.affected_surfaces and not any(item.path for item in draft.evidence):
        missing.append("missing affected surface or file")
    if draft.confidence == "low" and not draft.evidence:
        missing.append("insufficient evidence for low-confidence claim")
    return (len(missing) > 0, missing)


def file_contains_secret_pattern(path_text: str, excerpt: str) -> bool:
    return bool(SECRET_PATTERN.search(excerpt) or SECRET_PATTERN.search(path_text))
