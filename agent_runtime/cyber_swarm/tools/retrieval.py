"""LangGraph-facing retrieval tools."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.repo import RepoIntelligence
from cyber_swarm.models.retrieval import RetrievedContext, RetrievalQuery
from cyber_swarm.models.skills import RoutedSkills
from cyber_swarm.rag.code_retrieval import search_code
from cyber_swarm.rag.skill_retrieval import search_skills


def execute_retrieval_query(
    query: RetrievalQuery,
    repo: RepoIntelligence,
    routed_skills: RoutedSkills,
) -> list[RetrievedContext]:
    project_root = Path(repo.project_root)

    if query.target == "skills":
        results = search_skills(
            query.query,
            routed_skills,
            project_root,
            agent_type=query.agent_type,
            max_results=query.max_results,
        )
    elif query.target == "code":
        results = search_code(
            query.query,
            repo,
            max_results=query.max_results,
            filters=query.filters,
        )
    else:
        results = []

    return [
        RetrievedContext(
            id=result.id,
            query_id=query.id,
            source_type=result.source_type,
            source_path=result.source_path,
            title=result.title,
            excerpt=result.excerpt,
            score=result.score,
            reason=result.reason,
            line_start=result.line_start,
            line_end=result.line_end,
            context_category=result.context_category,
            is_supporting=result.is_supporting,
        )
        for result in results
    ]
