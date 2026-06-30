"""Lightweight symbol and route extraction for evidence packs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from cyber_swarm.evidence.env_config import is_env_config_path

PYTHON_DEF = re.compile(r"^\s*def\s+(\w+)")
PYTHON_DECORATOR_ROUTE = re.compile(
    r"^\s*@(?:app|router)\.(get|post|put|patch|delete|route|api_route)\(\s*[\"']([^\"']+)"
)
PYTHON_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(HTTPBearer|Depends|APIRouter|OAuth2PasswordBearer)")
TS_EXPORT_FN = re.compile(r"^\s*export\s+(?:async\s+)?function\s+(\w+)")
TS_HOOK = re.compile(r"^\s*export\s+(?:const|function)\s+(use[A-Z]\w+)")
TS_HANDLER = re.compile(r"^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b")
SUPABASE_CLIENT = re.compile(r"\b(createClient|createBrowserClient|createServerClient)\s*\(")
ENV_KEY = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=")


@dataclass(frozen=True)
class SymbolHit:
    symbol: str
    line_start: int
    line_end: int
    kind: str
    route: str | None = None


def extract_python_symbols(lines: list[str]) -> list[SymbolHit]:
    hits: list[SymbolHit] = []
    for index, line in enumerate(lines, start=1):
        if match := PYTHON_DEF.match(line):
            hits.append(
                SymbolHit(
                    symbol=match.group(1),
                    line_start=index,
                    line_end=min(index + 8, len(lines)),
                    kind="function",
                )
            )
        if match := PYTHON_DECORATOR_ROUTE.match(line):
            hits.append(
                SymbolHit(
                    symbol=f"{match.group(1).upper()} {match.group(2)}",
                    line_start=index,
                    line_end=min(index + 10, len(lines)),
                    kind="route_decorator",
                    route=match.group(2),
                )
            )
        if match := PYTHON_ASSIGN.match(line):
            hits.append(
                SymbolHit(
                    symbol=f"{match.group(1)}={match.group(2)}",
                    line_start=index,
                    line_end=min(index + 3, len(lines)),
                    kind="auth_helper",
                )
            )
        if "HTTPBearer" in line or "auto_error" in line.lower():
            hits.append(
                SymbolHit(
                    symbol="_bearer_scheme" if "HTTPBearer" in line else "auth_config",
                    line_start=index,
                    line_end=min(index + 3, len(lines)),
                    kind="auth_config",
                )
            )
        if "CurrentUser" in line or "get_current_user" in line:
            hits.append(
                SymbolHit(
                    symbol="CurrentUser" if "CurrentUser" in line else "get_current_user",
                    line_start=index,
                    line_end=min(index + 6, len(lines)),
                    kind="dependency",
                )
            )
    return hits


def extract_typescript_symbols(lines: list[str]) -> list[SymbolHit]:
    hits: list[SymbolHit] = []
    for index, line in enumerate(lines, start=1):
        if match := TS_EXPORT_FN.match(line):
            hits.append(
                SymbolHit(
                    symbol=match.group(1),
                    line_start=index,
                    line_end=min(index + 8, len(lines)),
                    kind="function",
                )
            )
        if match := TS_HOOK.match(line):
            hits.append(
                SymbolHit(
                    symbol=match.group(1),
                    line_start=index,
                    line_end=min(index + 10, len(lines)),
                    kind="hook",
                )
            )
        if match := TS_HANDLER.match(line):
            hits.append(
                SymbolHit(
                    symbol=f"handler {match.group(1)}",
                    line_start=index,
                    line_end=min(index + 12, len(lines)),
                    kind="route_handler",
                )
            )
        if match := SUPABASE_CLIENT.search(line):
            hits.append(
                SymbolHit(
                    symbol=match.group(1),
                    line_start=index,
                    line_end=min(index + 5, len(lines)),
                    kind="storage_client",
                )
            )
    return hits


def extract_config_symbols(lines: list[str], path: str) -> list[SymbolHit]:
    hits: list[SymbolHit] = []
    basename = path.replace("\\", "/").split("/")[-1].lower()
    if basename in {"package.json", "package-lock.json"}:
        hits.append(
            SymbolHit(
                symbol="package manifest",
                line_start=1,
                line_end=min(len(lines), 20),
                kind="dependency_manifest",
            )
        )
        return hits

    for index, line in enumerate(lines, start=1):
        if match := ENV_KEY.match(line):
            hits.append(
                SymbolHit(
                    symbol=match.group(1),
                    line_start=index,
                    line_end=index,
                    kind="env_key",
                )
            )
    return hits


def extract_symbols(lines: list[str], path: str) -> list[SymbolHit]:
    lower = path.lower()
    if is_env_config_path(path):
        return extract_config_symbols(lines, path)
    if lower.endswith(".py"):
        return extract_python_symbols(lines)
    if lower.endswith((".ts", ".tsx", ".js", ".jsx")):
        return extract_typescript_symbols(lines)
    if "config" in lower or lower.endswith(".json"):
        return extract_config_symbols(lines, path)
    return []
