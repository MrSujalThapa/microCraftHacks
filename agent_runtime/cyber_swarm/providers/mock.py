"""Deterministic mock provider for tests and offline runs."""

from __future__ import annotations

import json
from typing import Any

from cyber_swarm.providers.base import ProviderCallResult


class MockProvider:
    def __init__(self, model: str = "mock") -> None:
        self.model = model
        self._calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        purpose: str,
        max_output_tokens: int | None = None,
    ) -> ProviderCallResult:
        self._calls.append(
            {
                "purpose": purpose,
                "model": self.model,
                "systemLength": len(system),
                "userLength": len(user),
                "maxOutputTokens": max_output_tokens,
                "mock": True,
            }
        )
        payload = _mock_payload(purpose, user)
        return ProviderCallResult(
            purpose=purpose,
            model=self.model,
            elapsed_ms=0.0,
            payload=payload,
            prompt_tokens=max(1, (len(system) + len(user)) // 4),
            completion_tokens=min(120, max_output_tokens or 120),
            total_tokens=max(1, (len(system) + len(user)) // 4) + min(120, max_output_tokens or 120),
        )

    def call_log(self) -> list[dict[str, Any]]:
        return list(self._calls)


class UnusableConfirmationMockProvider(MockProvider):
    """Returns empty confirmations so tests can exercise deterministic fallback."""

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        purpose: str,
        max_output_tokens: int | None = None,
    ) -> ProviderCallResult:
        self._calls.append(
            {
                "purpose": purpose,
                "model": self.model,
                "systemLength": len(system),
                "userLength": len(user),
                "maxOutputTokens": max_output_tokens,
                "mock": True,
                "unusable": True,
            }
        )
        return ProviderCallResult(
            purpose=purpose,
            model=self.model,
            elapsed_ms=0.0,
            payload={"confirmations": [], "reject_all": False},
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
        )


def _mock_payload(purpose: str, user: str) -> dict[str, Any]:
    if purpose not in {"demo_findings", "demo_findings_repair"}:
        return {"status": "mock", "purpose": purpose}

    try:
        task = json.loads(user)
    except json.JSONDecodeError:
        return {"confirmations": [], "reject_all": True}

    if purpose == "demo_findings_repair":
        original = task.get("original", {})
        candidates = original.get("deterministicCandidates", [])
    else:
        candidates = task.get("deterministicCandidates", [])

    if not isinstance(candidates, list) or not candidates:
        return {"confirmations": [], "reject_all": True}

    first = candidates[0]
    if not isinstance(first, dict):
        return {"confirmations": [], "reject_all": True}

    candidate_id = str(first.get("candidateId", "draft-det-secret-1"))
    return {
        "confirmations": [
            {
                "candidateId": candidate_id,
                "confirmed": True,
                "why_qa_misses_this": "CI secret scanners may ignore local env templates.",
                "why_code_review_misses_this": "Reviewers treat env examples as non-production.",
                "suggested_regression_test": "Fail CI when credential-like assignments appear in tracked config.",
                "recommended_fix": "Move the secret to runtime env injection and rotate exposed credentials.",
            }
        ],
        "reject_all": False,
    }
