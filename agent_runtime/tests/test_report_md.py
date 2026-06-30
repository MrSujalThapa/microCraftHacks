"""Tests for Markdown findings report generation."""

from __future__ import annotations

import json
from pathlib import Path

from cyber_swarm.schemas.report_md import build_markdown_report, derive_markdown_path, write_markdown_report


def _sample_output() -> dict:
    return {
        "version": 1,
        "scanId": "2026-06-29T12-00-00-000Z",
        "status": "completed",
        "startedAt": "2026-06-29T12:00:00.000Z",
        "completedAt": "2026-06-29T12:05:00.000Z",
        "metrics": {
            "summary": {
                "verifiedCount": 1,
                "rejectedCount": 1,
                "needsEvidenceCount": 0,
                "severityCounts": {"high": 1},
            },
            "retrieval": {
                "selectedContext": [
                    {
                        "sourcePath": "src/auth.ts",
                        "reason": "auth middleware context",
                    }
                ]
            },
        },
        "verifiedFindings": [
            {
                "id": "verified-draft-auth-1",
                "title": "Auth boundary gap",
                "vulnerability_class": "broken-access-control",
                "claim": "Auth middleware should protect login routes.",
                "affected_surfaces": ["/api/login"],
                "affected_files": ["src/auth.ts"],
                "evidence": [
                    {
                        "type": "file",
                        "explanation": "Auth middleware on login handler",
                        "path": "src/auth.ts",
                        "route": "/api/login",
                        "line_start": 10,
                        "line_end": 20,
                    }
                ],
                "impact_hypothesis": "Unauthorized API access.",
                "attack_path": "Review auth middleware coverage.",
                "safe_reproduction": {
                    "mode": "static-proof",
                    "steps": ["Inspect src/auth.ts without live requests."],
                    "expected_result": "Document missing auth checks.",
                    "safety_notes": ["No live exploit execution."],
                },
                "confidence": "medium",
                "severity": "high",
                "demo_ready": True,
                "demo_reason": "High-confidence verified finding with strong ranking score",
                "ranking_rationale": {
                    "total_score": 0.71,
                    "factors": ["High-impact auth surface"],
                },
                "selected_skills": ["example-skill"],
            }
        ],
        "rejectedFindings": [
            {
                "draft_id": "draft-unsupported",
                "title": "Speculative issue",
                "reason": "Missing evidence refs",
                "source": "verifier",
            }
        ],
        "needsMoreEvidenceFindings": [],
    }


def test_derive_markdown_path():
    assert derive_markdown_path("scan-test-findings.json") == "scan-test-findings.md"


def test_build_markdown_report_includes_required_sections():
    markdown = build_markdown_report(_sample_output())

    assert "# Cyber Swarm Findings Report" in markdown
    assert "## Executive summary" in markdown
    assert "## Target / scan summary" in markdown
    assert "## Severity counts" in markdown
    assert "## Routed playbooks" in markdown
    assert "## Activated specialists" in markdown
    assert "## Demo-ready findings" in markdown
    assert "## Rejected / downgraded findings" in markdown
    assert "**Evidence (redacted)**" in markdown
    assert "**Safe reproduction**" in markdown
    assert "**Concrete fix plan**" in markdown
    assert "verified-draft-auth-1" in markdown
    assert "Speculative issue" in markdown


def test_markdown_report_never_contains_raw_secrets():
    output = _sample_output()
    output["verifiedFindings"][0]["evidence"][0]["snippet"] = "SUPABASE_SERVICE_ROLE_KEY=super-secret-value"
    markdown = build_markdown_report(output)
    assert "super-secret-value" not in markdown
    assert "<REDACTED_SECRET>" in markdown


def test_write_markdown_report_creates_file(tmp_path: Path):
    output_path = tmp_path / "scan-test-findings.json"
    output_path.write_text(json.dumps(_sample_output()), encoding="utf-8")

    markdown_path = write_markdown_report(str(output_path), _sample_output())

    assert markdown_path == str(tmp_path / "scan-test-findings.md")
    assert Path(markdown_path).exists()
    content = Path(markdown_path).read_text(encoding="utf-8")
    assert "Auth boundary gap" in content
