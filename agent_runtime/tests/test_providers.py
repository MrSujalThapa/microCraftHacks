"""Tests for provider factory and mock provider."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cyber_swarm.providers.factory import create_provider
from cyber_swarm.providers.mock import MockProvider
from cyber_swarm.providers.openai_provider import OpenAIProvider


def test_create_provider_defaults_to_mock():
    provider = create_provider("mock", "mock-model")
    assert isinstance(provider, MockProvider)
    assert provider.model == "mock-model"


def test_create_provider_requires_openai_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        create_provider("openai", "gpt-5-mini")


def test_mock_provider_records_calls_without_network():
    provider = MockProvider()
    result = provider.complete_json(system="sys", user="user", purpose="recon")
    assert result.payload["purpose"] == "recon"
    assert provider.call_log()[0]["mock"] is True


def test_openai_provider_repairs_invalid_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeCompletions:
        def __init__(self) -> None:
            self.responses = [
                MagicMock(
                    choices=[MagicMock(message=MagicMock(content="not-json"))],
                    usage=MagicMock(prompt_tokens=1, completion_tokens=2, total_tokens=3),
                ),
                MagicMock(
                    choices=[MagicMock(message=MagicMock(content='{"ok": true}'))],
                    usage=MagicMock(prompt_tokens=4, completion_tokens=5, total_tokens=9),
                ),
            ]
            self.index = 0

        def create(self, **_kwargs):
            response = self.responses[self.index]
            self.index += 1
            return response

    fake_client = MagicMock()
    fake_client.chat.completions = FakeCompletions()

    with patch("openai.OpenAI", return_value=fake_client):
        provider = OpenAIProvider(model="gpt-5-mini", api_key="test-key", timeout_seconds=5)
        result = provider.complete_json(system="sys", user="user", purpose="recon")

    assert result.payload == {"ok": True}
    assert result.repaired is True
    assert provider.call_log()[0]["repaired"] is True


def test_openai_provider_parses_valid_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    payload = {"reviews": []}

    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=json.dumps(payload)))],
        usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
    )

    with patch("openai.OpenAI", return_value=fake_client):
        provider = OpenAIProvider(model="gpt-5-mini", api_key="test-key", timeout_seconds=5)
        result = provider.complete_json(system="sys", user="user", purpose="verifier")

    assert result.payload == payload
    assert result.total_tokens == 15
