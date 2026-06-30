"""Runtime execution configuration."""

from __future__ import annotations

from dataclasses import dataclass


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

    @property
    def is_demo(self) -> bool:
        return self.mode in {"demo", "fast"}

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
