"""LangGraph workflow state definitions."""

from __future__ import annotations

from typing import Any, TypedDict


class GraphState(TypedDict, total=False):
    scan_report_path: str
    routed_skills_path: str
    output_path: str
    scan_report: dict[str, Any]
    routed_skills: dict[str, Any]
    draft_findings: list[Any]
    verified_findings: list[Any]
    rejected_findings: list[Any]
    metrics: dict[str, Any]
    output: dict[str, Any]
