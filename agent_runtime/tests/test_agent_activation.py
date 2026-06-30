"""Tests that agent activation is decoupled from routed skill count."""

from __future__ import annotations

import json
from pathlib import Path

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.recon import run_recon
from cyber_swarm.bridge import run_bridge
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfacesResult,
)
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill


def _cli_runtime_input(tmp_path: Path, skill_count: int) -> RuntimeInput:
    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=3,
            by_category={"typescript": 1, "json": 1, "config": 1},
            files=[
                FileInventoryItem(path="src/cli/index.ts", category="typescript"),
                FileInventoryItem(path="package.json", category="json"),
                FileInventoryItem(path=".swarm/config.json", category="config"),
            ],
        ),
        surfaces=SurfacesResult(),
    )
    selected = [
        SelectedSkill(
            name=f"skill-{index}",
            path=f"skills/external/skill-{index}/SKILL.md",
            score=0.9 - index * 0.01,
            reasons=[f"matched keyword: security-{index}"],
            agent_types=["recon"],
        )
        for index in range(skill_count)
    ]
    return RuntimeInput(
        scan_report_path=tmp_path / "scan.json",
        routed_skills_path=tmp_path / "routed.json",
        repo=repo,
        routed_skills=RoutedSkills(
            report_path=str(tmp_path / "scan.json"),
            routed_at="2026-06-29T12:01:00.000Z",
            selected=selected,
        ),
    )


def test_four_routed_skills_does_not_mean_four_agents(tmp_path: Path):
    runtime_input = _cli_runtime_input(tmp_path, skill_count=4)
    recon = run_recon(runtime_input, [])
    hypotheses = run_attack_planner(runtime_input, recon, [])

    assert len(runtime_input.routed_skills.selected) == 4
    assert len(hypotheses) != 4
    assert len(hypotheses) >= 1
    assert {hypothesis.agent_type for hypothesis in hypotheses} <= {
        "secrets",
        "dependency",
        "config",
        "auth",
        "api",
        "storage",
        "ai",
    }


def test_agents_run_with_zero_routed_skills(tmp_path: Path):
    runtime_input = _cli_runtime_input(tmp_path, skill_count=0)
    recon = run_recon(runtime_input, [])
    hypotheses = run_attack_planner(runtime_input, recon, [])

    assert len(runtime_input.routed_skills.selected) == 0
    assert recon.selected_agent_targets
    assert hypotheses


def test_bridge_activation_fields_decouple_skills_from_agents(tmp_path: Path):
    scan_report_path = tmp_path / "scan-cli.json"
    routed_skills_path = tmp_path / "routed-skills.json"
    output_path = tmp_path / "scan-cli-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {
                    "totalFiles": 2,
                    "byCategory": {"typescript": 1, "json": 1},
                    "files": [
                        {"path": "src/cli/index.ts", "category": "typescript"},
                        {"path": "package.json", "category": "json"},
                    ],
                },
                "surfaces": {"routes": [], "api": [], "auth": [], "dataModels": []},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [
                    {
                        "name": f"skill-{index}",
                        "path": f"skills/external/skill-{index}/SKILL.md",
                        "score": 0.8,
                        "reasons": ["matched keyword: security"],
                        "agentTypes": ["recon"],
                    }
                    for index in range(4)
                ],
            }
        ),
        encoding="utf-8",
    )

    output = run_bridge(scan_report_path, routed_skills_path, output_path)
    activation = output["metrics"]["activation"]

    assert activation["skillsRouted"] == 4
    assert activation["agentsPlanned"] >= 1
    assert activation["agentsRun"] >= 1
    assert activation["agentsPlanned"] != activation["skillsRouted"]
    assert isinstance(activation["agentTypes"], list)
    assert activation["agentTypes"]
