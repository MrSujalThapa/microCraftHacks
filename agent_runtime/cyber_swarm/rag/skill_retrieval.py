"""Skill retrieval over routed skills."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.rag.scoring import score_tokens
from cyber_swarm.rag.skill_loader import load_skill_sections

DEFAULT_MAX_RESULTS = 8
DEFAULT_MAX_CHARS = 4000


def _score_skill(skill: SelectedSkill, query: str, project_root: Path) -> tuple[float, str, str]:
    absolute_path = project_root / skill.path
    section_excerpt = ""
    if absolute_path.exists():
        sections = load_skill_sections(absolute_path, max_chars=DEFAULT_MAX_CHARS)
        if sections:
            section_excerpt = sections[0].content

    score, reason = score_tokens(
        query,
        skill.name,
        skill.path,
        " ".join(skill.reasons),
        " ".join(skill.agent_types),
        section_excerpt,
    )
    bonus = min(skill.score, 1.0) * 0.2
    return min(score + bonus, 1.0), reason, section_excerpt or skill.name.replace("-", " ")


def search_skills(
    query: str,
    routed_skills: RoutedSkills,
    project_root: Path,
    *,
    agent_type: str | None = None,
    max_results: int = DEFAULT_MAX_RESULTS,
) -> list[RetrievedContext]:
    candidates: list[tuple[float, SelectedSkill, str, str]] = []

    for skill in routed_skills.selected:
        if agent_type and agent_type not in skill.agent_types:
            continue
        score, reason, excerpt = _score_skill(skill, query, project_root)
        if score <= 0:
            continue
        candidates.append((score, skill, reason, excerpt))

    candidates.sort(key=lambda item: item[0], reverse=True)

    results: list[RetrievedContext] = []
    for index, (score, skill, reason, excerpt) in enumerate(candidates[:max_results]):
        results.append(
            RetrievedContext(
                id=f"skill-{index + 1}",
                query_id="",
                source_type="skill",
                source_path=skill.path,
                title=skill.name,
                excerpt=redact_secrets(excerpt[:DEFAULT_MAX_CHARS]),
                score=round(score, 3),
                reason=reason,
            )
        )

    return results
