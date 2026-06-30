"""Shared agent helpers without specialist imports."""

from __future__ import annotations

import re

from cyber_swarm.models.agents import SafeReproduction
from cyber_swarm.models.runtime import RuntimeInput

SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*\S+"
)


def skills_for_agent(runtime_input: RuntimeInput, agent_type: str) -> list[str]:
    return [
        skill.name
        for skill in runtime_input.routed_skills.selected
        if agent_type in skill.agent_types
    ][:3]


def static_reproduction(steps: list[str], expected: str) -> SafeReproduction:
    return SafeReproduction(
        mode="static-proof",
        steps=steps,
        expected_result=expected,
        safety_notes=[
            "Static analysis only; no runtime probing or destructive actions.",
            "Review redacted excerpts locally before any active testing.",
        ],
    )


def file_contains_secret_pattern(path_text: str, excerpt: str) -> bool:
    return bool(SECRET_PATTERN.search(excerpt) or SECRET_PATTERN.search(path_text))
