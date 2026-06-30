"""Env/config path detection and safe redacted assignment snippets."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from cyber_swarm.evidence.ignore import should_ignore_scanned_path
from cyber_swarm.models.repo import RepoIntelligence
from cyber_swarm.rag.redaction import redact_secrets

ENV_BASENAME = re.compile(r"^\.env(?:\.[\w.-]+)?$", re.IGNORECASE)
ENV_SUFFIX = re.compile(r"\.env(?:\.[\w.-]+)?$", re.IGNORECASE)
KEY_VALUE_CONFIG_NAMES = frozenset(
    {
        ".properties",
        "application.properties",
        "application.yml",
        "application.yaml",
    }
)

_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:"
    r"changeme|change[-_ ]?me|example|placeholder|dummy|todo|"
    r"replace[-_ ]?me|insert[-_ ]?here|your[-_ ]?|xxx+|"
    r"<\s*(?:your|insert|replace|secret|key|token|password)[^>]*>|"
    r"\$\{[^}]+\}|"
    r"__+[A-Z_]+__+"
    r")"
)

_CREDENTIAL_LIKE_VALUE = re.compile(
    r"(?i)(?:"
    r"sk-[a-z0-9]{10,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"sb_[a-z0-9_]{10,}|"
    r"eyJ[a-z0-9_-]{10,}\.[a-z0-9_-]+\.|"
    r"[a-z0-9+/=]{24,}"
    r")"
)


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def basename(path: str) -> str:
    return PurePosixPath(normalize_path(path)).name


def is_env_config_path(path: str) -> bool:
    """True for committed env files and key=value config surfaces."""
    normalized = normalize_path(path)
    if not normalized or should_ignore_scanned_path(normalized):
        return False

    name = basename(normalized).lower()
    if name.startswith(".env"):
        return True
    if ENV_SUFFIX.search(normalized):
        return True
    if name in KEY_VALUE_CONFIG_NAMES:
        return True
    if name.endswith((".properties", ".ini", ".cfg", ".conf")):
        return True
    return False


def is_env_example_path(path: str) -> bool:
    normalized = normalize_path(path).lower()
    name = basename(normalized)
    return ".example" in name or name.endswith((".sample", ".template", ".dist"))


def env_assignment_value(raw_line: str) -> str | None:
    match = re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.*)$", raw_line)
    if not match:
        return None
    value = match.group(1).strip()
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        value = value[1:-1]
    return value


def is_placeholder_env_value(value: str | None) -> bool:
    if value is None:
        return True
    stripped = value.strip()
    if not stripped:
        return True
    if _PLACEHOLDER_VALUE.match(stripped):
        return True
    if stripped.startswith(("<", "[", "{")) and stripped.endswith((">", "]", "}")):
        return True
    return False


def is_credential_like_env_value(value: str | None) -> bool:
    if value is None or not value.strip():
        return False
    return bool(_CREDENTIAL_LIKE_VALUE.search(value.strip()))


def should_treat_env_key_as_secret(path: str, key: str, raw_line: str) -> bool:
    """Skip example placeholders unless the value looks like a live credential."""
    value = env_assignment_value(raw_line)
    if is_env_example_path(path):
        return is_credential_like_env_value(value)
    if is_placeholder_env_value(value):
        return is_credential_like_env_value(value)
    return True


def format_env_assignment_snippet(raw_line: str) -> str:
    """Redact assignment values while preserving key names and line shape."""
    return redact_secrets(raw_line.rstrip("\n"))


def collect_env_config_paths(
    repo: RepoIntelligence,
    context_paths: set[str],
) -> list[str]:
    """Collect env/config paths from inventory and retrieval context, env files first."""
    ordered: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        normalized = normalize_path(path)
        if normalized in seen or not is_env_config_path(normalized):
            return
        seen.add(normalized)
        ordered.append(normalized)

    for path in sorted(context_paths):
        add(path)

    for item in repo.inventory.files:
        add(item.path)

    return ordered
