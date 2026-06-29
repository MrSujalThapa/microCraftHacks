"""Deterministic agentic retrieval loop helpers."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cyber_swarm.rag.categories import CATEGORY_PRIORITY

from cyber_swarm.models.retrieval import RetrievedContext, RetrievalQuery
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.tools.retrieval import execute_retrieval_query

MAX_RETRIEVAL_ITERATIONS = 2
SUFFICIENCY_SCORE_THRESHOLD = 0.35
SUFFICIENCY_MIN_RESULTS = 1


def _collect_surface_terms(runtime_input: RuntimeInput) -> list[str]:
    terms: list[str] = []
    for route in [*runtime_input.repo.surfaces.routes, *runtime_input.repo.surfaces.api]:
        for segment in route.path.split("/"):
            if segment and segment not in {"api", "v1"}:
                terms.append(segment)
    for auth in runtime_input.repo.surfaces.auth:
        terms.extend(part.replace(".ts", "").replace(".py", "") for part in auth.file.split("/"))
    for stack in runtime_input.repo.stack:
        terms.append(stack.name.lower())
    return terms[:6]


def _default_agent_type(runtime_input: RuntimeInput) -> str:
    for skill in runtime_input.routed_skills.selected:
        if skill.agent_types:
            return skill.agent_types[0]
    return "recon"


def plan_retrieval(runtime_input: RuntimeInput, iteration: int = 1) -> RetrievalQuery:
    terms = _collect_surface_terms(runtime_input) or ["security", "auth", "api"]
    query = " ".join(["security", *terms[:4]])
    target = "code" if iteration == 1 else "skills"

    return RetrievalQuery(
        id=f"query-{iteration}",
        agent_type=_default_agent_type(runtime_input),
        query=query,
        target=target,
        max_results=8,
        hypothesis_id="hypothesis-local-1",
    )


def rewrite_query(current: RetrievalQuery, runtime_input: RuntimeInput) -> RetrievalQuery:
    next_iteration = int(current.id.split("-")[-1]) + 1
    extra_terms = ["route", "handler", "middleware", "skill", "validation"]
    missing = [term for term in extra_terms if term not in current.query.lower()]
    rewritten = f"{current.query} {' '.join(missing[:3])}".strip()
    target = "skills" if current.target == "code" else "code"

    return RetrievalQuery(
        id=f"query-{next_iteration}",
        agent_type=current.agent_type,
        query=rewritten,
        target=target,
        max_results=current.max_results,
        hypothesis_id=current.hypothesis_id,
    )


def retrieve_for_query(
    query: RetrievalQuery,
    runtime_input: RuntimeInput,
) -> list[RetrievedContext]:
    primary = execute_retrieval_query(query, runtime_input.repo, runtime_input.routed_skills)
    secondary_target = "skills" if query.target == "code" else "code"
    secondary = execute_retrieval_query(
        RetrievalQuery(
            id=f"{query.id}-{secondary_target}",
            agent_type=query.agent_type,
            query=query.query,
            target=secondary_target,
            max_results=max(3, query.max_results // 2),
            hypothesis_id=query.hypothesis_id,
        ),
        runtime_input.repo,
        runtime_input.routed_skills,
    )

    combined = primary + secondary
    combined.sort(key=lambda item: item.score, reverse=True)
    return combined


def grade_context(results: list[RetrievedContext]) -> dict[str, Any]:
    strong = [result for result in results if result.score >= SUFFICIENCY_SCORE_THRESHOLD]
    top_score = max((result.score for result in results), default=0.0)
    sufficient = len(strong) >= SUFFICIENCY_MIN_RESULTS or top_score >= 0.5

    return {
        "sufficient": sufficient,
        "topScore": round(top_score, 3),
        "resultCount": len(results),
        "strongResultCount": len(strong),
        "rationale": "Enough local evidence collected"
        if sufficient
        else "Need broader local retrieval coverage",
        "missingEvidence": []
        if sufficient
        else ["additional route/auth context", "supporting skill guidance"],
    }


def finalize_context(results: list[RetrievedContext], max_items: int = 8) -> list[RetrievedContext]:
    deduped: dict[str, RetrievedContext] = {}
    for result in sorted(
        results,
        key=lambda item: (CATEGORY_PRIORITY.get(item.context_category, 0), item.score),
        reverse=True,
    ):
        key = result.source_path or result.id
        if key not in deduped:
            deduped[key] = result

    primary = [item for item in deduped.values() if item.context_category != "test"]
    supporting = [item for item in deduped.values() if item.context_category == "test"]

    selected = primary[:max_items]
    if len(selected) < max_items and supporting:
        remaining = max_items - len(selected)
        selected.extend(supporting[:remaining])

    return selected[:max_items]


def serialize_context(items: list[RetrievedContext]) -> list[dict[str, Any]]:
    return [asdict(item) for item in items]
