"""Secret detection helpers for evidence packs."""

from __future__ import annotations

import re

from cyber_swarm.evidence.models import EvidencePack

CREDENTIAL_KEY_MARKERS = ("KEY", "SECRET", "TOKEN", "PASSWORD")

_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*\S+"
)

_SENSITIVE_TOKEN = re.compile(
    r"(?i)\b("
    r"credential|secret|password|token|api[_-]?key|private[_-]?key|"
    r"service[_-]?role|pii|ssn|credit.?card|user.?data|email.?address|"
    r"database.?url|connection.?string|internal.?infra|stack.?trace|"
    r"debug.?info|env.?var|admin.?key|"
    r"side.?effect|tool.?call|"
    r"llm|openai|anthropic|embedding|prompt.?injection|"
    r"supabase|postgres|redis|aws|stripe|"
    r"SUPABASE_SERVICE_ROLE_KEY|OPENAI_API_KEY|API_KEY"
    r")\b"
)


def is_credential_env_key(symbol: str) -> bool:
    upper = symbol.upper()
    if upper.startswith(("NEXT_PUBLIC_", "VITE_", "PUBLIC_", "REACT_APP_")):
        return False
    if "ANON" in upper and "KEY" in upper:
        return False
    return any(marker in upper for marker in CREDENTIAL_KEY_MARKERS)


def file_contains_secret_pattern(path_text: str, excerpt: str) -> bool:
    return bool(_SECRET_PATTERN.search(excerpt) or _SECRET_PATTERN.search(path_text))


def is_secret_evidence_pack(pack: EvidencePack) -> bool:
    if pack.kind == "env_key" and pack.symbol and is_credential_env_key(pack.symbol):
        return True
    return file_contains_secret_pattern(pack.path, pack.snippet)


def sensitive_exposure_match(text: str) -> bool:
    return _SENSITIVE_TOKEN.search(text) is not None
