"""Tests for the agentic retrieval loop."""

from __future__ import annotations

import json
from pathlib import Path

from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.loop import (
    finalize_context,
    grade_context,
    plan_retrieval,
    retrieve_for_query,
    rewrite_query,
)
from cyber_swarm.models.runtime import RuntimeInput


def _runtime_input(tmp_path: Path) -> RuntimeInput:
    skill_dir = tmp_path / "skills" / "api-security"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "# Workflow\nValidate API auth middleware and schema checks.\n",
        encoding="utf-8",
    )
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "auth.ts").write_text(
        "export function requireAuth() { return middleware; }\n",
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
    routed = RoutedSkills(
        report_path=str(tmp_path / "scan.json"),
        routed_at="2026-06-29T12:01:00.000Z",
        selected=[
            SelectedSkill(
                name="testing-api-security-with-owasp-top-10",
                path="skills/api-security/SKILL.md",
                score=0.8,
                reasons=["matched keyword: api"],
                agent_types=["api"],
            )
        ],
    )
    return RuntimeInput(
        scan_report_path=tmp_path / "scan.json",
        routed_skills_path=tmp_path / "routed.json",
        repo=repo,
        routed_skills=routed,
    )


def test_plan_rewrite_and_grade_are_deterministic(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
    first_query = plan_retrieval(runtime_input)
    first_results = retrieve_for_query(first_query, runtime_input)
    first_grade = grade_context(first_results)

    rewritten = rewrite_query(first_query, runtime_input)
    second_results = retrieve_for_query(rewritten, runtime_input)
    combined = finalize_context(first_results + second_results)

    assert first_query.target == "code"
    assert rewritten.target == "skills"
    assert len(combined) >= 1
    assert "resultCount" in first_grade


def test_workflow_includes_retrieval_attempts(tmp_path: Path):
    scan_report_path = tmp_path / "scan.json"
    routed_skills_path = tmp_path / "routed.json"
    output_path = tmp_path / "scan-findings.json"

    runtime_input = _runtime_input(tmp_path)
    scan_report_path.write_text(
        json.dumps(
            {
                "version": runtime_input.repo.version,
                "scannedAt": runtime_input.repo.scanned_at,
                "projectRoot": runtime_input.repo.project_root,
                "inventory": {
                    "totalFiles": runtime_input.repo.inventory.total_files,
                    "byCategory": runtime_input.repo.inventory.by_category,
                    "files": [
                        {"path": item.path, "category": item.category}
                        for item in runtime_input.repo.inventory.files
                    ],
                },
                "surfaces": {
                    "routes": [],
                    "api": [
                        {
                            "path": route.path,
                            "file": route.file,
                            "framework": route.framework,
                        }
                        for route in runtime_input.repo.surfaces.api
                    ],
                    "auth": [],
                    "dataModels": [],
                },
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": runtime_input.routed_skills.routed_at,
                "selected": [
                    {
                        "name": skill.name,
                        "path": skill.path,
                        "score": skill.score,
                        "reasons": skill.reasons,
                        "agentTypes": skill.agent_types,
                    }
                    for skill in runtime_input.routed_skills.selected
                ],
            }
        ),
        encoding="utf-8",
    )

    output = run_workflow(scan_report_path, routed_skills_path, output_path)

    assert output["metrics"]["retrieval"]["attempts"]
    assert output["metrics"]["retrieval"]["selectedContext"]
    assert "plan_retrieval" in output["metrics"]["stages"]
