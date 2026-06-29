"""Shared provider interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderCallResult:
    purpose: str
    model: str
    elapsed_ms: float
    payload: dict[str, Any]
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    repaired: bool = False


class AgentProvider(Protocol):
    model: str

    def complete_json(self, *, system: str, user: str, purpose: str) -> ProviderCallResult:
        """Return structured JSON from the provider."""

    def call_log(self) -> list[dict[str, Any]]:
        """Return metadata for completed calls."""
