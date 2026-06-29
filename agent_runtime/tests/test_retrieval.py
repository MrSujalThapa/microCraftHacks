"""Tests for local retrieval tools."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.code_retrieval import search_code
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.rag.skill_retrieval import search_skills


def test_search_skills_returns_routed_matches(tmp_path: Path):
    skill_dir = tmp_path / "skills" / "api-security"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(
        "# When to Use\nUse for API schema validation and OWASP testing.\n",
        encoding="utf-8",
    )

    routed = RoutedSkills(
        report_path=str(tmp_path / "scan.json"),
        routed_at="2026-06-29T12:00:00.000Z",
        selected=[
            SelectedSkill(
                name="testing-api-security-with-owasp-top-10",
                path="skills/api-security/SKILL.md",
                score=0.8,
                reasons=["matched keyword: api", "matched keyword: owasp"],
                agent_types=["api"],
            )
        ],
    )

    results = search_skills("api owasp validation", routed, tmp_path)

    assert len(results) == 1
    assert results[0].source_type == "skill"
    assert results[0].source_path == "skills/api-security/SKILL.md"
    assert results[0].score > 0
    assert "api" in results[0].excerpt.lower()


def test_search_code_returns_inventory_matches(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    auth_file = src_dir / "auth.ts"
    auth_file.write_text(
        "export function requireAuth(req, res, next) {\n  // middleware\n}\n",
        encoding="utf-8",
    )

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=1,
            by_category={"typescript": 1},
            files=[FileInventoryItem(path="src/auth.ts", category="typescript")],
        ),
        surfaces=SurfacesResult(
            api=[SurfaceRoute(path="/api/login", file="src/auth.ts", framework="express")]
        ),
    )

    results = search_code("auth middleware login", repo)

    assert len(results) >= 1
    assert any(result.source_path == "src/auth.ts" for result in results)
    assert all(result.score > 0 for result in results)
    assert all(result.excerpt for result in results)


def test_redact_secrets_masks_common_patterns():
    redacted = redact_secrets("api_key=super-secret-token sk-1234567890abcdef")

    assert "super-secret-token" not in redacted
    assert "[REDACTED]" in redacted
