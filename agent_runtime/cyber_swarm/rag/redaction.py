"""Redact likely secrets from retrieved excerpts and report output."""

from __future__ import annotations

import re

REDACTED_SECRET = "<REDACTED_SECRET>"

# Preserve key names: KEY=<REDACTED_SECRET>
_NAMED_SECRET = re.compile(
    r"(?i)\b("
    r"[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)"
    r"|api[_-]?key|secret|password|token|private[_-]?key"
    r")\s*[:=]\s*\S+"
)

_SK_TOKEN = re.compile(r"\bsk-[A-Za-z0-9]{10,}\b")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{8,}\b")

SECRET_PATTERNS = (_NAMED_SECRET, _SK_TOKEN, _AWS_KEY, _BEARER)

# Detect raw secret values that must not appear in output.
RAW_SECRET = re.compile(
    r"(?i)\b("
    r"[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)"
    r"|api[_-]?key|secret|password|token|private[_-]?key"
    r")\s*[:=]\s*(?!<?REDACTED_SECRET>?)\S+"
)
RAW_SK = re.compile(r"\bsk-[A-Za-z0-9]{10,}\b")
RAW_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

RAW_SECRET_PATTERNS = (RAW_SECRET, RAW_SK, RAW_AWS)


def _replace_named_secret(match: re.Match[str]) -> str:
    key = match.group(1)
    return f"{key}={REDACTED_SECRET}"


def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    redacted = _NAMED_SECRET.sub(_replace_named_secret, redacted)
    redacted = _SK_TOKEN.sub(REDACTED_SECRET, redacted)
    redacted = _AWS_KEY.sub(REDACTED_SECRET, redacted)
    redacted = _BEARER.sub(f"Bearer {REDACTED_SECRET}", redacted)
    return redacted


def contains_raw_secret(text: str) -> bool:
    if not text:
        return False
    return any(pattern.search(text) for pattern in RAW_SECRET_PATTERNS)
