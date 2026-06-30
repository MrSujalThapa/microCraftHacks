"""Tests for demo rejection diagnostics."""

from __future__ import annotations

from cyber_swarm.demo.diagnostics import format_rejection_diagnostics, print_rejection_diagnostics


def test_format_rejection_diagnostics_includes_category_and_reason():
    lines = format_rejection_diagnostics(
        {
            "verifiedFindings": [],
            "rejectedFindings": [
                {
                    "title": "Sample finding",
                    "vulnerability_class": "secret-exposure",
                    "reason": "evidence missing evidence_pack_id",
                    "failed_checks": ["evidence missing evidence_pack_id"],
                }
            ],
        }
    )
    assert lines
    assert "secret-exposure" in lines[0]
    assert "evidence_pack_id" in lines[0]


def test_print_rejection_diagnostics_skips_when_verified(capsys):
    print_rejection_diagnostics(
        {
            "verifiedFindings": [{"id": "verified-1"}],
            "rejectedFindings": [{"title": "noise"}],
        }
    )
    captured = capsys.readouterr()
    assert "Verifier rejections" not in captured.out
