"""LangGraph workflow state definitions."""

from __future__ import annotations

from typing import Any, TypedDict

from cyber_swarm.models.retrieval import RetrievedContext, RetrievalQuery
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.rag.normalize import normalize_runtime_input


class GraphState(TypedDict, total=False):
    scan_report_path: str
    routed_skills_path: str
    output_path: str
    runtime_input: RuntimeInput
    scan_report: dict[str, Any]
    routed_skills: dict[str, Any]
    draft_findings: list[Any]
    verified_findings: list[Any]
    rejected_findings: list[Any]
    metrics: dict[str, Any]
    output: dict[str, Any]
    retrieval_queries: list[RetrievalQuery]
    current_query: RetrievalQuery | None
    retrieved_context: list[RetrievedContext]
    selected_context: list[RetrievedContext]
    retrieval_attempts: list[dict[str, Any]]
    retrieval_iteration: int
    retrieval_sufficient: bool
