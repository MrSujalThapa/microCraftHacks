"""Code retrieval over scan inventory and project files."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.repo import FileInventoryItem, RepoIntelligence
from cyber_swarm.models.retrieval import RetrievedContext
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
) -> list[RetrievedContext]:
    project_root = Path(repo.project_root)
    candidates: list[tuple[float, FileInventoryItem, str, str, int | None, int | None]] = []

    for item in _iter_relevant_files(repo):
        absolute_path = project_root / item.path
        excerpt, line_start, line_end = _load_excerpt(absolute_path, query)
        score, reason = score_tokens(query, item.path, item.category, excerpt)
        if score <= 0:
            continue
        candidates.append((score, item, reason, excerpt, line_start, line_end))

    for route in [*repo.surfaces.routes, *repo.surfaces.api]:
        score, reason = score_tokens(query, route.path, route.file, route.framework or "")
        if score <= 0:
            continue
        candidates.append(
            (
                score,
                FileInventoryItem(path=route.file, category="surface"),
                f"{reason}; surface {route.path}",
                f"Surface route {route.path} mapped to {route.file}",
                None,
                None,
            )
        )

    candidates.sort(key=lambda item: item[0], reverse=True)

    results: list[RetrievedContext] = []
    for index, (score, item, reason, excerpt, line_start, line_end) in enumerate(
        candidates[:max_results]
    ):
        source_type = "surface" if item.category == "surface" else "file"
        results.append(
            RetrievedContext(
                id=f"code-{index + 1}",
                query_id="",
                source_type=source_type,
                source_path=item.path,
                excerpt=redact_secrets(excerpt[:DEFAULT_MAX_CHARS]),
                score=round(score, 3),
                reason=reason,
                line_start=line_start,
                line_end=line_end,
            )
        )

    return results
