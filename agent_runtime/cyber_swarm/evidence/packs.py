"""Build line-level evidence packs from scan surfaces and retrieved context."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.evidence.env_config import (
    collect_env_config_paths,
    format_env_assignment_snippet,
    should_treat_env_key_as_secret,
)
from cyber_swarm.evidence.extract import extract_symbols
from cyber_swarm.evidence.models import EvidencePack, SurfaceType
from cyber_swarm.evidence.reader import excerpt_lines, read_lines
from cyber_swarm.evidence.secret_packs import is_credential_env_key
from cyber_swarm.models.repo import RepoIntelligence

MAX_PACKS = 48
MAX_PACKS_PER_FILE = 4
MAX_PACKS_PER_ENV_FILE = 8
MAX_ENV_CONFIG_PACKS = 16

_AUTH_HINTS = ("auth", "session", "jwt", "oauth", "login", "guard", "middleware", "bearer")
_API_HINTS = ("route", "api", "handler", "endpoint", "controller")
_STORAGE_HINTS = ("supabase", "storage", "s3", "bucket", "database", "prisma")
_AI_HINTS = ("openai", "anthropic", "llm", "embedding", "model", "ai")
_CONFIG_HINTS = (".env", "config", "settings", "docker-compose", "yaml", "yml", "toml")
_DEPENDENCY_HINTS = ("package.json", "requirements.txt", "pyproject.toml", "poetry.lock")


def classify_surface_type(path: str, symbol_kind: str, route: str | None = None) -> SurfaceType:
    normalized = path.replace("\\", "/").lower()
    if symbol_kind == "env_key":
        return "config"
    if symbol_kind in {"auth_config", "auth_helper", "dependency"} or any(h in normalized for h in _AUTH_HINTS):
        return "auth"
    if symbol_kind in {"route_decorator", "route_handler"} or route or any(h in normalized for h in _API_HINTS):
        return "api"
    if symbol_kind == "storage_client" or any(h in normalized for h in _STORAGE_HINTS):
        return "storage"
    if any(h in normalized for h in _AI_HINTS):
        return "ai"
    if symbol_kind in {"dependency_manifest"} or any(h in normalized for h in _CONFIG_HINTS):
        return "config"
    if any(normalized.endswith(h) for h in _DEPENDENCY_HINTS):
        return "dependency"
    return "source"


def _collect_candidate_paths(
    repo: RepoIntelligence,
    context_paths: set[str],
) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        normalized = path.replace("\\", "/")
        if normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    for route in [*repo.surfaces.routes, *repo.surfaces.api]:
        add(route.file)

    for item in repo.surfaces.auth:
        add(item.file)
    for item in repo.surfaces.data_models:
        add(item.file)

    for path in sorted(context_paths):
        add(path)

    for file_item in repo.inventory.files:
        add(file_item.path)

    return ordered


def _snippet_for_hit(path: str, lines: list[str], hit) -> str:
    if hit.kind == "env_key":
        line_idx = hit.line_start - 1
        if 0 <= line_idx < len(lines):
            return format_env_assignment_snippet(lines[line_idx])
    return excerpt_lines(lines, hit.line_start, hit.line_end)


def _append_packs_for_path(
    *,
    path: str,
    lines: list[str],
    packs: list[EvidencePack],
    per_file: dict[str, int],
    max_packs: int,
    max_per_file: int,
    max_env_config_packs: int | None = None,
) -> None:
    symbols = extract_symbols(lines, path)
    if not symbols:
        return

    env_config_count = sum(1 for pack in packs if pack.kind == "env_key")

    for hit in symbols:
        if len(packs) >= max_packs:
            break
        if per_file.get(path, 0) >= max_per_file:
            break
        if hit.kind == "env_key" and max_env_config_packs is not None:
            if env_config_count >= max_env_config_packs:
                break
            key = hit.symbol or ""
            if not is_credential_env_key(key):
                continue
            line_idx = hit.line_start - 1
            raw_line = lines[line_idx] if 0 <= line_idx < len(lines) else ""
            if not should_treat_env_key_as_secret(path, key, raw_line):
                continue

        snippet = _snippet_for_hit(path, lines, hit)
        if not snippet.strip():
            continue

        surface_type = classify_surface_type(path, hit.kind, hit.route)
        packs.append(
            EvidencePack(
                id="",
                path=path,
                line_start=hit.line_start,
                line_end=hit.line_end,
                snippet=snippet,
                symbol=hit.symbol,
                surface_type=surface_type,
                kind=hit.kind,
                route=hit.route,
            )
        )
        per_file[path] = per_file.get(path, 0) + 1
        if hit.kind == "env_key":
            env_config_count += 1


def _reindex_packs(packs: list[EvidencePack]) -> list[EvidencePack]:
    reindexed: list[EvidencePack] = []
    for index, pack in enumerate(packs, start=1):
        reindexed.append(
            EvidencePack(
                id=f"ep-{index:03d}",
                path=pack.path,
                line_start=pack.line_start,
                line_end=pack.line_end,
                snippet=pack.snippet,
                symbol=pack.symbol,
                surface_type=pack.surface_type,
                kind=pack.kind,
                route=pack.route,
            )
        )
    return reindexed


def build_evidence_packs(
    project_root: Path,
    repo: RepoIntelligence,
    context_paths: set[str],
    *,
    max_packs: int = MAX_PACKS,
) -> list[EvidencePack]:
    env_paths = collect_env_config_paths(repo, context_paths)
    env_path_set = set(env_paths)
    other_paths = [path for path in _collect_candidate_paths(repo, context_paths) if path not in env_path_set]

    packs: list[EvidencePack] = []
    per_file: dict[str, int] = {}

    for path in env_paths:
        lines = read_lines(project_root, path)
        if not lines:
            continue
        _append_packs_for_path(
            path=path,
            lines=lines,
            packs=packs,
            per_file=per_file,
            max_packs=max_packs,
            max_per_file=MAX_PACKS_PER_ENV_FILE,
            max_env_config_packs=MAX_ENV_CONFIG_PACKS,
        )

    for path in other_paths:
        if len(packs) >= max_packs:
            break
        if per_file.get(path, 0) >= MAX_PACKS_PER_FILE:
            continue

        lines = read_lines(project_root, path)
        if not lines:
            continue

        _append_packs_for_path(
            path=path,
            lines=lines,
            packs=packs,
            per_file=per_file,
            max_packs=max_packs,
            max_per_file=MAX_PACKS_PER_FILE,
        )

    return _reindex_packs(packs)


def packs_by_id(packs: list[EvidencePack]) -> dict[str, EvidencePack]:
    return {pack.id: pack for pack in packs}
