"""Deterministic mock provider for tests and offline runs."""

from __future__ import annotations

from typing import Any

from cyber_swarm.providers.base import ProviderCallResult


class MockProvider:
    def __init__(self, model: str = "mock") -> None:
        self.model = model
        self._calls: list[dict[str, Any]] = []

    def complete_json(self, *, system: str, user: str, purpose: str) -> ProviderCallResult:
        self._calls.append(
            {
                "purpose": purpose,
                "model": self.model,
                "systemLength": len(system),
                "userLength": len(user),
                "mock": True,
            }
        )
        return ProviderCallResult(
            purpose=purpose,
            model=self.model,
            elapsed_ms=0.0,
            payload={"status": "mock", "purpose": purpose},
        )

    def call_log(self) -> list[dict[str, Any]]:
        return list(self._calls)
