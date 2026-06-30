"""Provider factory."""

from __future__ import annotations

import os

from cyber_swarm.providers.base import AgentProvider
from cyber_swarm.providers.mock import MockProvider
from cyber_swarm.providers.openai_provider import OpenAIProvider


def create_provider(
    provider_name: str,
    model: str,
    *,
    timeout_seconds: float = 60.0,
) -> AgentProvider:
    normalized = provider_name.strip().lower()
    if normalized == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise ValueError("OPENAI_API_KEY is required when provider is openai")
        return OpenAIProvider(model=model, api_key=api_key, timeout_seconds=timeout_seconds)

    if normalized == "local":
        raise ValueError("Local provider is not implemented yet")

    return MockProvider(model=model or "mock")
