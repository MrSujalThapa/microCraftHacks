import json
from pathlib import Path

import pytest

from cyber_swarm.bridge import run_bridge
from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.runner import build_parser, main


def test_build_parser_has_bridge_flags():
    parser = build_parser()
    help_text = parser.format_help()
    assert "--scan-report" in help_text
    assert "--routed-skills" in help_text
    assert "--output" in help_text
    assert "--mode" in help_text
    assert "--from-cache" in help_text


def test_main_demo_mode_exits_zero(tmp_path: Path):
    scan_report_path = tmp_path / "scan-demo.json"
    routed_skills_path = tmp_path / "routed-demo.json"
    output_path = tmp_path / "scan-demo-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {
                    "totalFiles": 0,
                    "byCategory": {},
                    "files": [],
                },
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [],
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--scan-report",
                str(scan_report_path),
                "--routed-skills",
                str(routed_skills_path),
                "--output",
                str(output_path),
                "--provider",
                "mock",
                "--mode",
                "demo",
            ]
        )
        == 0
    )
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["metrics"]["runtime"]["mode"] == "demo"


def test_main_fast_mode_alias_exits_zero(tmp_path: Path):
    scan_report_path = tmp_path / "scan-fast.json"
    routed_skills_path = tmp_path / "routed-fast.json"
    output_path = tmp_path / "scan-fast-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {"totalFiles": 0, "byCategory": {}, "files": []},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-06-29T12:01:00.000Z",
                "selected": [],
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "--scan-report",
                str(scan_report_path),
                "--routed-skills",
                str(routed_skills_path),
                "--output",
                str(output_path),
                "--provider",
                "mock",
                "--mode",
                "fast",
            ]
        )
        == 0
    )


def test_main_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_run_bridge_writes_empty_findings(tmp_path: Path):
    scan_report_path = tmp_path / "scan-test.json"
    routed_skills_path = tmp_path / "routed-skills.json"
    output_path = tmp_path / "scan-test-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "stack": [
                    {
                        "name": "typescript",
                        "confidence": "high",
                        "evidence": ["package.json"],
                    }
                ],
                "inventory": {
                    "totalFiles": 1,
                    "byCategory": {"typescript": 1},
                    "files": [{"path": "src/index.ts", "category": "typescript"}],
                },
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
                        "name": "example-skill",
                        "path": "skills/example/SKILL.md",
                        "score": 0.8,
                        "reasons": ["matched keyword: security"],
                        "agentTypes": ["recon", "api"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    output = run_bridge(scan_report_path, routed_skills_path, output_path)

    assert output_path.exists()
    assert output["verifiedFindings"] == []
    assert isinstance(output["rejectedFindings"], list)
    markdown_path = output_path.with_suffix(".md")
    assert markdown_path.exists()
    assert "# Cyber Swarm Findings Report" in markdown_path.read_text(encoding="utf-8")
    assert output["metrics"]["verifier"]["verifiedCount"] == 0
    assert output["status"] == "completed"
    assert output["metrics"]["graph"] == "langgraph"
    assert output["metrics"]["load_input"]["normalized"] is True
    assert output["metrics"]["recon_agent"]["status"] == "completed"
    assert output["metrics"]["attack_planner"]["hypothesisCount"] >= 1

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["scanId"] == "2026-06-29T12-00-00-000Z"


def test_run_workflow_executes_all_stages(tmp_path: Path):
    scan_report_path = tmp_path / "scan.json"
    routed_skills_path = tmp_path / "routed.json"
    output_path = tmp_path / "scan-findings.json"

    scan_report_path.write_text(
        json.dumps(
            {
                "version": "0.1.0",
                "scannedAt": "2026-01-01T00:00:00.000Z",
                "projectRoot": str(tmp_path),
                "inventory": {
                    "totalFiles": 0,
                    "byCategory": {},
                    "files": [],
                },
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "reportPath": str(scan_report_path),
                "routedAt": "2026-01-01T00:01:00.000Z",
                "selected": [],
            }
        ),
        encoding="utf-8",
    )

    output = run_workflow(scan_report_path, routed_skills_path, output_path)

    assert output["metrics"]["stages"] == [
        "load_input",
        "plan_retrieval",
        "retrieve_context",
        "grade_context",
        "rewrite_query",
        "finalize_context",
        "build_evidence_packs",
        "build_attack_graph",
        "recon_agent",
        "attack_planner",
        "specialist_agents",
        "verifier",
        "dedup",
        "rank",
        "report_stub",
    ]
