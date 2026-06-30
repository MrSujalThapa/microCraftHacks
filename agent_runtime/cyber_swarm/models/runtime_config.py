"""Runtime execution configuration."""

from __future__ import annotations

from dataclasses import dataclass

_LATENCY_CAPS = frozenset({"fastest", "balanced", "thorough"})


@dataclass(frozen=True)
class RuntimeConfig:
    provider: str = "mock"
    model: str = "gpt-5-mini"
    max_selected_context: int = 8
    max_draft_findings: int = 3
    call_timeout_seconds: float = 60.0
    mode: str = "full"
    from_cache: bool = False
    max_model_calls: int | None = None
    max_specialists: int | None = None
    latency: str = "balanced"
    no_llm: bool = False
    force_llm: bool = False

    @property
    def is_demo(self) -> bool:
        return self.mode in {"demo", "fast"}

    @property
    def effective_latency(self) -> str:
        if self.is_demo:
            return self.latency if self.latency in _LATENCY_CAPS else "balanced"
        return self.latency if self.latency in _LATENCY_CAPS else "thorough"

    def llm_provider_enabled(self) -> bool:
        if self.no_llm:
            return False
        return self.provider in {"openai", "mock"}

    def effective_max_selected_context(self) -> int:
        if self.is_demo:
            return min(self.max_selected_context, 4)
        return self.max_selected_context

    def effective_max_draft_findings(self) -> int:
        if self.is_demo:
            return min(self.max_draft_findings, 2)
        return self.max_draft_findings

    def effective_max_model_calls(self) -> int:
        if self.max_model_calls is not None:
            return self.max_model_calls
        return 1 if self.is_demo else 999

    def effective_max_specialists(self) -> int:
        if self.max_specialists is not None:
            return self.max_specialists
        return 2 if self.is_demo else 999
