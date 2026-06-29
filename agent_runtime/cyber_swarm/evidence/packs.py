"""Build line-level evidence packs from scan surfaces and retrieved context."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.evidence.extract import extract_symbols
from cyber_swarm.evidence.models import EvidencePack, SurfaceType
from cyber_swarm.evidence.reader import excerpt_lines, read_lines
from cyber_swarm.models.repo import RepoIntelligence, SurfaceRoute

MAX_PACKS = 48
MAX_PACKS_PER_FILE = 4

_AUTH_HINTS = ("auth", "session", "jwt", "oauth", "login", "guard", "middleware", "bearer")
_API_HINTS = ("route", "api", "handler", "endpoint", "controller")
_STORAGE_HINTS = ("supabase", "storage", "s3", "bucket", "database", "prisma")
_AI_HINTS = ("openai", "anthropic", "llm", "embedding", "model", "ai")
_CONFIG_HINTS = (".env", "config", "settings", "docker-compose", "yaml", "yml", "toml")
_DEPENDENCY_HINTS = ("package.json", "requirements.txt", "pyproject.toml", "poetry.lock")


def classify_surface_type(path: str, symbol_kind: str, route: str | None = None) -> SurfaceType:
    normalized = path.replace("\\", "/").lower()
    if symbol_kind in {"auth_config", "auth_helper", "dependency"} or any(h in normalized for h in _AUTH_HINTS):
        return "auth"
    if symbol_kind in {"route_decorator", "route_handler"} or route or any(h in normalized for h in _API_HINTS):
        return "api"
    if symbol_kind == "storage_client" or any(h in normalized for h in _STORAGE_HINTS):
        return "storage"
    if any(h in normalized for h in _AI_HINTS):
        return "ai"
    if symbol_kind in {"env_key", "dependency_manifest"} or any(h in normalized for h in _CONFIG_HINTS):
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


def build_evidence_packs(
    project_root: Path,
    repo: RepoIntelligence,
    context_paths: set[str],
    *,
    max_packs: int = MAX_PACKS,
) -> list[EvidencePack]:
    packs: list[EvidencePack] = []
    per_file: dict[str, int] = {}
    pack_index = 0

    for path in _collect_candidate_paths(repo, context_paths):
        if len(packs) >= max_packs:
            break
        if per_file.get(path, 0) >= MAX_PACKS_PER_FILE:
            continue

        lines = read_lines(project_root, path)
        if not lines:
            continue

        symbols = extract_symbols(lines, path)
        if not symbols:
            continue

        for hit in symbols:
            if len(packs) >= max_packs:
                break
            if per_file.get(path, 0) >= MAX_PACKS_PER_FILE:
                break

            snippet = excerpt_lines(lines, hit.line_start, hit.line_end)
            if not snippet.strip():
                continue

            surface_type = classify_surface_type(path, hit.kind, hit.route)
            pack_index += 1
            pack_id = f"ep-{pack_index:03d}"
            packs.append(
                EvidencePack(
                    id=pack_id,
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

    return packs


def packs_by_id(packs: list[EvidencePack]) -> dict[str, EvidencePack]:
    return {pack.id: pack for pack in packs}
