"""Combined normalized runtime input."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyber_swarm.models.repo import RepoIntelligence
from cyber_swarm.models.skills import RoutedSkills


@dataclass(frozen=True)
class RuntimeInput:
    scan_report_path: Path
    routed_skills_path: Path
    repo: RepoIntelligence
    routed_skills: RoutedSkills
