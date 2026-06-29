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
                "scannedAt": "2026-06-29T12:00:00.000Z",
                "projectRoot": str(tmp_path),
                "stack": [{"name": "typescript"}],
                "inventory": {"totalFiles": 3},
            }
        ),
        encoding="utf-8",
    )
    routed_skills_path.write_text(
        json.dumps(
            {
                "selected": [
                    {
                        "name": "example-skill",
                        "agentTypes": ["recon", "api"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    output = run_bridge(scan_report_path, routed_skills_path, output_path)

    assert output_path.exists()
    assert output["verifiedFindings"] == []
    assert output["rejectedFindings"] == []
    assert output["status"] == "completed"
    assert output["metrics"]["graph"] == "langgraph"
    assert output["metrics"]["load_input"]["routedSkillCount"] == 1
    assert output["metrics"]["recon_stub"]["stackCount"] == 1
    assert output["metrics"]["specialist_stub"]["agentTypes"] == ["api", "recon"]
    assert output["metrics"]["verifier_stub"]["verifiedFindingCount"] == 0

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["scanId"] == "2026-06-29T12-00-00-000Z"


def test_run_workflow_executes_all_stages(tmp_path: Path):
    scan_report_path = tmp_path / "scan.json"
    routed_skills_path = tmp_path / "routed.json"
    output_path = tmp_path / "scan-findings.json"

    scan_report_path.write_text(json.dumps({"scannedAt": "2026-01-01T00:00:00.000Z"}), encoding="utf-8")
    routed_skills_path.write_text(json.dumps({"selected": []}), encoding="utf-8")

    output = run_workflow(scan_report_path, routed_skills_path, output_path)

    assert output["metrics"]["stages"] == [
        "load_input",
        "recon_stub",
        "specialist_stub",
        "verifier_stub",
        "report_stub",
    ]
