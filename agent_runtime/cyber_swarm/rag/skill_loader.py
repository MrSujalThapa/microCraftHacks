"""Load compact sections from SKILL.md files."""

from __future__ import annotations

import re
from pathlib import Path

from cyber_swarm.models.skills import LoadedSkillSection


SECTION_HEADERS = (
    "When to Use",
    "Prerequisites",
    "Workflow",
    "Verification",
    "Remediation",
    "Safety Notes",
)


def load_skill_sections(source_path: Path, max_chars: int = 4000) -> list[LoadedSkillSection]:
    if not source_path.exists() or not source_path.is_file():
        return []

    content = source_path.read_text(encoding="utf-8", errors="replace")
    sections: list[LoadedSkillSection] = []
    skill_name = source_path.parent.name

    for header in SECTION_HEADERS:
        pattern = re.compile(rf"(?m)^#{{1,3}}\s*{re.escape(header)}\s*$")
        match = pattern.search(content)
        if not match:
            continue

        start = match.end()
        next_header = re.search(r"(?m)^#{1,3}\s+", content[start:])
        end = start + next_header.start() if next_header else len(content)
        section_content = content[start:end].strip()
        if not section_content:
            continue

        sections.append(
            LoadedSkillSection(
                skill_name=skill_name,
                source_path=str(source_path),
                section=header,
                content=section_content[:max_chars],
            )
        )

    if sections:
        return sections

    return [
        LoadedSkillSection(
            skill_name=skill_name,
            source_path=str(source_path),
            section="summary",
            content=content[:max_chars],
        )
    ]
