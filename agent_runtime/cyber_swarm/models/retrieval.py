"""Typed models for agentic retrieval queries and context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AgentType = Literal[
    "recon",
    "auth",
    "api",
    "secrets",
    "injection",
    "availability",
    "business-logic",
    "runtime",
    "verifier",
    "reporter",
    "skill-evolution",
    "dependency",
]

RetrievalTarget = Literal["code", "skills", "capabilities"]
ContextCategory = Literal["source", "config", "route", "schema", "auth", "test", "skill"]


@dataclass(frozen=True)
class RetrievalQuery:
    id: str
    agent_type: str
    query: str
    target: RetrievalTarget
    max_results: int = 8
    hypothesis_id: str | None = None
    filters: dict[str, str | list[str]] | None = None


@dataclass(frozen=True)
class RetrievedContext:
    id: str
    query_id: str
    source_type: Literal["file", "skill", "capability", "surface"]
    excerpt: str
    score: float
    reason: str
    source_path: str | None = None
    title: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    context_category: ContextCategory = "source"
    is_supporting: bool = False
