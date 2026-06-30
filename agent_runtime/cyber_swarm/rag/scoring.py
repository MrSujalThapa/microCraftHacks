"""Deterministic keyword scoring for local retrieval."""

from __future__ import annotations

import re


def tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]+", text.lower()) if len(token) >= 2]


def score_tokens(query: str, *texts: str) -> tuple[float, str]:
    query_tokens = tokenize(query)
    if not query_tokens:
        return 0.0, "empty query"

    combined = " ".join(texts).lower()
    matched = [token for token in query_tokens if token in combined]
    if not matched:
        return 0.0, "no keyword overlap"

    score = len(matched) / len(query_tokens)
    return score, f"matched keywords: {', '.join(matched)}"
