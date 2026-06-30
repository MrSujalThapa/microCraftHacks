"""Context category classification for retrieval quality gating."""

from __future__ import annotations

import re
from typing import Literal

from cyber_swarm.models.repo import RepoIntelligence, SurfaceRoute

ContextCategory = Literal["source", "config", "route", "schema", "auth", "test", "skill"]

TEST_PATH_PATTERNS = (
    re.compile(r"(^|[/\\])tests?[/\\]", re.IGNORECASE),
    re.compile(r"__tests__", re.IGNORECASE),
    re.compile(r"\.(test|spec)\.[a-z0-9]+$", re.IGNORECASE),
    re.compile(r"(^|[/\\])test_[^/\\]+$", re.IGNORECASE),
    re.compile(r"_test\.py$", re.IGNORECASE),
)

AUTH_PATH_HINTS = ("auth", "session", "middleware", "login", "oauth", "jwt", "guard")
CONFIG_PATH_HINTS = (".env", "config.json", "config.ts", "settings", "docker-compose", "yaml", "yml")
SCHEMA_PATH_HINTS = ("schema.prisma", "models/", "model.", "migration", "schema.sql")

CATEGORY_PRIORITY: dict[ContextCategory, int] = {
    "source": 6,
    "auth": 5,
    "route": 5,
    "schema": 4,
    "config": 3,
    "skill": 2,
    "test": 0,
}


def is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(pattern.search(normalized) for pattern in TEST_PATH_PATTERNS)


def query_requests_tests(query: str, filters: dict[str, str | list[str]] | None = None) -> bool:
    lowered = query.lower()
    if any(token in lowered for token in ("test", "fixture", "mock", "spec")):
        return True
    if not filters:
        return False
    categories = filters.get("categories") or filters.get("category")
    if isinstance(categories, str):
        return categories == "test"
    if isinstance(categories, list):
        return "test" in categories
    return False


def classify_path(path: str, repo: RepoIntelligence | None = None) -> ContextCategory:
    normalized = path.replace("\\", "/").lower()

    if is_test_path(path):
        return "test"

    if any(hint in normalized for hint in AUTH_PATH_HINTS):
        return "auth"

    if any(hint in normalized for hint in SCHEMA_PATH_HINTS):
        return "schema"

    if any(normalized.endswith(hint) or hint in normalized for hint in CONFIG_PATH_HINTS):
        return "config"

    if repo is not None:
        for route in [*repo.surfaces.routes, *repo.surfaces.api]:
            if route.file.replace("\\", "/").lower() == normalized:
                return "route"

    return "source"


def classify_route_surface(route: SurfaceRoute) -> ContextCategory:
    return "route"


def classify_skill_path(path: str) -> ContextCategory:
    return "skill"


def rank_score(category: ContextCategory, score: float, *, supporting_test: bool = False) -> float:
    if category == "test" and not supporting_test:
        return score * 0.25
    bonus = {
        "source": 0.12,
        "auth": 0.15,
        "route": 0.14,
        "schema": 0.13,
        "config": 0.1,
        "skill": 0.08,
        "test": 0.0,
    }[category]
    return min(score + bonus, 1.0)
