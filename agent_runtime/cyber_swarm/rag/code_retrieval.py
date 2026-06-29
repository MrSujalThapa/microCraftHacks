"""Code retrieval over scan inventory and project files."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.repo import FileInventoryItem, RepoIntelligence
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.rag.categories import (
    classify_path,
    classify_route_surface,
    is_test_path,
    query_requests_tests,
    rank_score,
)
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.rag.scoring import score_tokens

DEFAULT_MAX_RESULTS = 8
DEFAULT_MAX_CHARS = 4000
RELEVANT_CATEGORIES = {
    "typescript",
    "javascript",
    "python",
    "java",
    "config",
    "json",
    "yaml",
    "docker",
}


def _load_excerpt(path: Path, query: str, max_chars: int = DEFAULT_MAX_CHARS) -> tuple[str, int | None, int | None]:
    if not path.exists() or not path.is_file():
        return "", None, None

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", None, None

    if len(content) <= max_chars:
        return content, 1, max(1, content.count("\n") + 1)

    query_tokens = query.lower().split()
    lines = content.splitlines()
    best_index = 0
    best_matches = -1
    for index, line in enumerate(lines):
        lowered = line.lower()
        matches = sum(1 for token in query_tokens if token and token in lowered)
        if matches > best_matches:
            best_matches = matches
            best_index = index

    start = max(best_index - 3, 0)
    end = min(start + 40, len(lines))
    excerpt_lines = lines[start:end]
    excerpt = "\n".join(excerpt_lines)[:max_chars]
    return excerpt, start + 1, end


def _iter_relevant_files(repo: RepoIntelligence) -> list[FileInventoryItem]:
    return [
        item
        for item in repo.inventory.files
        if item.category in RELEVANT_CATEGORIES
    ]


def search_code(
    query: str,
    repo: RepoIntelligence,
    *,
    max_results: int = DEFAULT_MAX_RESULTS,
    include_tests: bool = False,
    filters: dict[str, str | list[str]] | None = None,
) -> list[RetrievedContext]:
    project_root = Path(repo.project_root)
    allow_tests = include_tests or query_requests_tests(query, filters)
    candidates: list[tuple[float, FileInventoryItem, str, str, int | None, int | None, str, bool]] = []

    for item in _iter_relevant_files(repo):
        category = classify_path(item.path, repo)
        if category == "test" and not allow_tests:
            continue

        absolute_path = project_root / item.path
        excerpt, line_start, line_end = _load_excerpt(absolute_path, query)
        score, reason = score_tokens(query, item.path, item.category, excerpt)
        if score <= 0:
            continue

        ranked = rank_score(category, score, supporting_test=allow_tests and category == "test")
        candidates.append(
            (ranked, item, f"{reason}; category={category}", excerpt, line_start, line_end, category, False)
        )

    for route in [*repo.surfaces.routes, *repo.surfaces.api]:
        route_file = route.file
        if is_test_path(route_file) and not allow_tests:
            continue

        category = classify_route_surface(route)
        score, reason = score_tokens(query, route.path, route.file, route.framework or "")
        if score <= 0:
            continue

        ranked = rank_score(category, score)
        candidates.append(
            (
                ranked,
                FileInventoryItem(path=route.file, category="surface"),
                f"{reason}; surface {route.path}; category={category}",
                f"Surface route {route.path} mapped to {route.file}",
                None,
                None,
                category,
                False,
            )
        )

    for auth in repo.surfaces.auth:
        if is_test_path(auth.file) and not allow_tests:
            continue
        category = "auth"
        score, reason = score_tokens(query, auth.file, auth.type or "auth")
        if score <= 0:
            continue
        ranked = rank_score(category, score)
        candidates.append(
            (
                ranked,
                FileInventoryItem(path=auth.file, category="surface"),
                f"{reason}; auth boundary; category={category}",
                f"Auth boundary file {auth.file}",
                None,
                None,
                category,
                False,
            )
        )

    for model in repo.surfaces.data_models:
        if is_test_path(model.file) and not allow_tests:
            continue
        category = "schema"
        score, reason = score_tokens(query, model.file, model.name or "model")
        if score <= 0:
            continue
        ranked = rank_score(category, score)
        candidates.append(
            (
                ranked,
                FileInventoryItem(path=model.file, category="surface"),
                f"{reason}; schema model; category={category}",
                f"Data model {model.name or 'unknown'} in {model.file}",
                None,
                None,
                category,
                False,
            )
        )

    candidates.sort(key=lambda item: (item[0], item[6] != "test"), reverse=True)

    results: list[RetrievedContext] = []
    primary_added = 0
    for index, (score, item, reason, excerpt, line_start, line_end, category, _) in enumerate(candidates):
        if category == "test" and primary_added >= max(1, max_results - 1):
            continue
        if len(results) >= max_results:
            break

        is_supporting = category == "test" and primary_added > 0
        source_type = "surface" if item.category == "surface" else "file"
        results.append(
            RetrievedContext(
                id=f"code-{len(results) + 1}",
                query_id="",
                source_type=source_type,
                source_path=item.path,
                excerpt=redact_secrets(excerpt[:DEFAULT_MAX_CHARS]),
                score=round(score, 3),
                reason=reason,
                line_start=line_start,
                line_end=line_end,
                context_category=category,
                is_supporting=is_supporting,
            )
        )
        if category != "test":
            primary_added += 1

    return results
