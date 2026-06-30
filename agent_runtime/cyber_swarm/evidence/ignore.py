"""Path ignore rules aligned with TypeScript scanner ignore.ts."""

from __future__ import annotations

IGNORE_DIR_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "dist",
        "build",
        "out",
        ".next",
        "coverage",
        "vendor",
        ".turbo",
        ".pnpm-store",
        ".yarn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        "site-packages",
        ".cursor",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".cache",
    }
)

IGNORE_RELATIVE_PREFIXES = (".swarm/cache", ".swarm/reports")


def normalize_relative_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def should_ignore_scanned_path(rel_path: str) -> bool:
    normalized = normalize_relative_path(rel_path)
    if any(
        normalized == prefix or normalized.startswith(f"{prefix}/")
        for prefix in IGNORE_RELATIVE_PREFIXES
    ):
        return True
    for segment in normalized.split("/"):
        if segment in IGNORE_DIR_NAMES:
            return True
    return False
