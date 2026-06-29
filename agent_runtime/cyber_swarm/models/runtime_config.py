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
