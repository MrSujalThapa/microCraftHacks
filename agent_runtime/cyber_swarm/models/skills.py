"""Typed models for routed and loaded skills."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SelectedSkill:
    name: str
    path: str
    score: float
    reasons: list[str]
    agent_types: list[str]


@dataclass(frozen=True)
class RoutedSkills:
    report_path: str
    routed_at: str
    selected: list[SelectedSkill] = field(default_factory=list)


@dataclass(frozen=True)
class LoadedSkillSection:
    skill_name: str
    source_path: str
    section: str
    content: str
