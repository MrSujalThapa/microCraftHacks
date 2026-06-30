"""Safe file reading under scanned target root."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.evidence.ignore import should_ignore_scanned_path
from cyber_swarm.rag.redaction import redact_secrets

MAX_FILE_BYTES = 256_000
MAX_SNIPPET_LINES = 12


def resolve_safe_path(project_root: Path, relative_path: str) -> Path | None:
    normalized = relative_path.replace("\\", "/").strip()
    if not normalized or should_ignore_scanned_path(normalized):
        return None

    root = project_root.resolve()
    candidate = (root / normalized).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None

    if not candidate.is_file():
        return None
    return candidate


def read_lines(project_root: Path, relative_path: str) -> list[str] | None:
    path = resolve_safe_path(project_root, relative_path)
    if path is None:
        return None
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def excerpt_lines(
    lines: list[str],
    line_start: int,
    line_end: int | None = None,
) -> str:
    start_idx = max(line_start - 1, 0)
    end_idx = min(line_end or (line_start + MAX_SNIPPET_LINES - 1), len(lines))
    end_idx = min(end_idx, start_idx + MAX_SNIPPET_LINES)
    snippet = "\n".join(lines[start_idx:end_idx])
    return redact_secrets(snippet)
