"""OpenAI provider with structured JSON output."""

from __future__ import annotations

import json
import time
from typing import Any

from cyber_swarm.providers.base import ProviderCallResult
from cyber_swarm.providers.prompts import REPAIR_SYSTEM_PROMPT


class OpenAIProvider:
    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        timeout_seconds: float = 60.0,
    ) -> None:
        from openai import OpenAI

        self.model = model
        self._client = OpenAI(api_key=api_key, timeout=timeout_seconds)
        self._calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        purpose: str,
        max_output_tokens: int | None = None,
    ) -> ProviderCallResult:
        started = time.perf_counter()
        try:
            content, usage, repaired = self._complete_with_optional_repair(
                system,
                user,
                max_output_tokens=max_output_tokens,
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

            try:
                payload = json.loads(content)
            except json.JSONDecodeError as error:
                raise ValueError(f"OpenAI provider returned invalid JSON for {purpose}") from error

            if not isinstance(payload, dict):
                raise ValueError(f"OpenAI provider expected JSON object for {purpose}")

            result = ProviderCallResult(
                purpose=purpose,
                model=self.model,
                elapsed_ms=elapsed_ms,
                payload=payload,
                prompt_tokens=_usage_value(usage, "prompt_tokens"),
                completion_tokens=_usage_value(usage, "completion_tokens"),
                total_tokens=_usage_value(usage, "total_tokens"),
                repaired=repaired,
            )
            self._calls.append(
                {
                    "purpose": purpose,
                    "model": self.model,
                    "elapsedMs": elapsed_ms,
                    "promptTokens": result.prompt_tokens,
                    "completionTokens": result.completion_tokens,
                    "totalTokens": result.total_tokens,
                    "repaired": repaired,
                    "maxOutputTokens": max_output_tokens,
                }
            )
            return result
        except Exception as error:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            self._calls.append(
                {
                    "purpose": purpose,
                    "model": self.model,
                    "elapsedMs": elapsed_ms,
                    "error": str(error),
                    "maxOutputTokens": max_output_tokens,
                }
            )
            raise

    def call_log(self) -> list[dict[str, Any]]:
        return list(self._calls)

    def _complete_with_optional_repair(
        self,
        system: str,
        user: str,
        *,
        max_output_tokens: int | None = None,
    ) -> tuple[str, Any, bool]:
        content, usage = self._request(system, user, max_output_tokens=max_output_tokens)
        if not content.strip():
            content, usage = self._request(system, user, max_output_tokens=None)
        try:
            json.loads(content)
            return content, usage, False
        except json.JSONDecodeError:
            repair_user = (
                "The previous response was invalid JSON.\n"
                f"Invalid response:\n{content}\n\n"
                f"Original task:\n{user}"
            )
            repaired_content, repaired_usage = self._request(
                REPAIR_SYSTEM_PROMPT,
                repair_user,
                max_output_tokens=max_output_tokens,
            )
            return repaired_content, repaired_usage, True

    def _request(
        self,
        system: str,
        user: str,
        *,
        max_output_tokens: int | None = None,
    ) -> tuple[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }
        if max_output_tokens is not None:
            kwargs["max_completion_tokens"] = max_output_tokens
        response = self._client.chat.completions.create(**kwargs)
        message = response.choices[0].message.content if response.choices else None
        if not message:
            return "", getattr(response, "usage", None)
        return message, getattr(response, "usage", None)


def _usage_value(usage: Any, field: str) -> int | None:
    if usage is None:
        return None
    value = getattr(usage, field, None)
    return int(value) if isinstance(value, int) else None
