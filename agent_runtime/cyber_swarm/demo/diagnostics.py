"""Demo-mode rejection diagnostics for CLI output."""

from __future__ import annotations

from typing import Any


def format_rejection_diagnostics(output: dict[str, Any]) -> list[str]:
    """Return concise human-readable rejection lines from a findings payload."""
    lines: list[str] = []
    rejected = output.get("rejectedFindings", [])
    if not isinstance(rejected, list):
        return lines

    for item in rejected:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("draft_id") or "unknown draft")
        category = str(item.get("vulnerability_class") or item.get("category") or "unknown")
        reason = str(item.get("reason") or "rejected")
        failed = item.get("failed_checks") or item.get("missing_evidence") or []
        if isinstance(failed, list) and failed:
            detail = "; ".join(str(check) for check in failed[:3])
        else:
            detail = reason[:160]
        lines.append(f"- [{category}] {title}: {detail}")

    needs = output.get("needsMoreEvidenceFindings", [])
    if isinstance(needs, list):
        for item in needs:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("draft_id") or "unknown draft")
            reason = str(item.get("reason") or "needs more evidence")
            lines.append(f"- [needs-evidence] {title}: {reason[:160]}")

    return lines


def print_rejection_diagnostics(output: dict[str, Any]) -> None:
    verified = output.get("verifiedFindings", [])
    verified_count = len(verified) if isinstance(verified, list) else 0
    if verified_count > 0:
        return

    lines = format_rejection_diagnostics(output)
    if not lines:
        return

    print("  Verifier rejections:")
    for line in lines[:8]:
        print(f"    {line}")
