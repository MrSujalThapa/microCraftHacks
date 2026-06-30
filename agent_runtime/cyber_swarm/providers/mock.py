"""Deterministic mock provider for tests and offline runs."""

from __future__ import annotations

import json
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
        payload = _mock_payload(purpose, user)
        return ProviderCallResult(
            purpose=purpose,
            model=self.model,
            elapsed_ms=0.0,
            payload=payload,
            prompt_tokens=max(1, (len(system) + len(user)) // 4),
            completion_tokens=32,
            total_tokens=max(1, (len(system) + len(user)) // 4) + 32,
        )

    def call_log(self) -> list[dict[str, Any]]:
        return list(self._calls)


def _mock_payload(purpose: str, user: str) -> dict[str, Any]:
    if purpose != "demo_findings":
        return {"status": "mock", "purpose": purpose}

    try:
        task = json.loads(user)
    except json.JSONDecodeError:
        return {"findings": [], "reject_all": True}

    packs = task.get("evidencePacks", [])
    if not isinstance(packs, list) or not packs:
        return {"findings": [], "reject_all": True}

    secret_pack = None
    for pack in packs:
        if not isinstance(pack, dict):
            continue
        surface = str(pack.get("surfaceType", ""))
        symbol = str(pack.get("symbol", ""))
        if surface == "config" or "secret" in symbol.lower() or "key" in symbol.lower():
            secret_pack = pack
            break
    if secret_pack is None:
        secret_pack = packs[0]

    pack_id = str(secret_pack.get("id", "pack-1"))
    path = str(secret_pack.get("path", "config.env"))
    symbol = str(secret_pack.get("symbol", "API_KEY"))
    return {
        "findings": [
            {
                "id": "draft-mock-1",
                "title": f"Hardcoded {symbol} in {path}",
                "vulnerability_class": "secret-exposure",
                "claim": f"{symbol} in {path} is assigned in tracked configuration without secret-manager injection.",
                "specialist": "secrets-config",
                "agent_type": "secrets",
                "affected_surfaces": [],
                "evidence_pack_ids": [pack_id],
                "impact_hypothesis": "Exposed secrets in tracked files can enable credential theft.",
                "attack_path": f"Inspect {path} for {symbol}.",
                "confidence": "high",
                "why_qa_misses_this": "CI secret scanners may ignore local env templates.",
                "why_code_review_misses_this": "Reviewers treat env examples as non-production.",
                "suggested_regression_test": "Fail CI when credential-like assignments appear in tracked config.",
            }
        ],
        "reject_all": False,
    }
