"""Render demo-ready Markdown findings reports."""

from __future__ import annotations

from typing import Any


def derive_markdown_path(json_path: str) -> str:
    if json_path.lower().endswith(".json"):
        return f"{json_path[:-5]}.md"
    return f"{json_path}.md"


def _severity_counts(output: dict[str, Any]) -> dict[str, int]:
    summary = output.get("metrics", {}).get("summary", {})
    counts = summary.get("severityCounts", {})
    if isinstance(counts, dict):
        return {str(key): int(value) for key, value in counts.items() if isinstance(value, int)}
    return {}


def _format_evidence(evidence: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        location_parts: list[str] = []
        if item.get("route"):
            location_parts.append(str(item["route"]))
        if item.get("path"):
            path = str(item["path"])
            if item.get("line_start") is not None:
                end = item.get("line_end")
                suffix = f":{item['line_start']}"
                if end is not None:
                    suffix = f":{item['line_start']}-{end}"
                path = f"{path}{suffix}"
            location_parts.append(path)
        location = " @ ".join(location_parts) if location_parts else "unknown"
        explanation = item.get("explanation", "")
        evidence_type = item.get("type", "evidence")
        lines.append(f"- **[{evidence_type}]** {location} — {explanation}")
    return lines


def _format_reproduction(reproduction: dict[str, Any]) -> list[str]:
    if not isinstance(reproduction, dict):
        return ["- _No safe reproduction steps recorded._"]

    lines = [f"- **Mode:** `{reproduction.get('mode', 'unknown')}`"]
    steps = reproduction.get("steps", [])
    if isinstance(steps, list) and steps:
        lines.append("- **Steps:**")
        for step in steps:
            if isinstance(step, str):
                lines.append(f"  1. {step}")
    expected = reproduction.get("expected_result")
    if isinstance(expected, str) and expected:
        lines.append(f"- **Expected result:** {expected}")
    notes = reproduction.get("safety_notes", [])
    if isinstance(notes, list) and notes:
        lines.append("- **Safety notes:**")
        for note in notes:
            if isinstance(note, str):
                lines.append(f"  - {note}")
    return lines


def _format_verified_finding(index: int, finding: dict[str, Any]) -> list[str]:
    lines = [
        f"### {index}. {finding.get('title', 'Untitled finding')}",
        "",
        f"- **ID:** `{finding.get('id', 'unknown')}`",
        f"- **Severity:** {finding.get('severity', 'unknown')}  "
        f"**Confidence:** {finding.get('confidence', 'unknown')}",
        f"- **Class:** `{finding.get('vulnerability_class', 'unknown')}`",
        "",
        "**Claim**",
        "",
        str(finding.get("claim", "")),
        "",
        "**Impact**",
        "",
        str(finding.get("impact_hypothesis", "")),
        "",
        "**Attack path**",
        "",
        str(finding.get("attack_path", "")),
        "",
    ]

    surfaces = finding.get("affected_surfaces", [])
    if isinstance(surfaces, list) and surfaces:
        lines.extend(["**Affected surfaces**", ""])
        for surface in surfaces:
            if isinstance(surface, str):
                lines.append(f"- `{surface}`")
        lines.append("")

    files = finding.get("affected_files", [])
    if isinstance(files, list) and files:
        lines.extend(["**Affected files**", ""])
        for path in files:
            if isinstance(path, str):
                lines.append(f"- `{path}`")
        lines.append("")

    evidence = finding.get("evidence", [])
    lines.extend(["**Evidence**", ""])
    if isinstance(evidence, list):
        lines.extend(_format_evidence(evidence) or ["- _No evidence recorded._"])
    else:
        lines.append("- _No evidence recorded._")
    lines.append("")

    reproduction = finding.get("safe_reproduction", {})
    lines.extend(["**Safe reproduction**", ""])
    lines.extend(_format_reproduction(reproduction if isinstance(reproduction, dict) else {}))
    lines.append("")

    lines.extend(
        [
            "**Suggested fix**",
            "",
            "> Run `swarm fix "
            f"{finding.get('id', '<finding-id>')} --report <findings.json>` for a concrete patch plan.",
            "",
        ]
    )

    rationale = finding.get("ranking_rationale", {})
    if isinstance(rationale, dict):
        factors = rationale.get("factors", [])
        if isinstance(factors, list) and factors:
            lines.extend(["**Ranking factors**", ""])
            for factor in factors:
                if isinstance(factor, str):
                    lines.append(f"- {factor}")
            total = rationale.get("total_score")
            if isinstance(total, (int, float)):
                lines.append(f"- Total score: `{total:.2f}`")
            lines.append("")

    return lines


def _format_rejected_summary(rejected: list[Any]) -> list[str]:
    if not rejected:
        return ["_No rejected findings._", ""]

    lines = [f"**Total rejected:** {len(rejected)}", ""]
    for index, item in enumerate(rejected[:20], start=1):
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("draft_id") or "Rejected draft"
        reason = item.get("reason", "No reason recorded")
        source = item.get("source", "unknown")
        lines.append(f"{index}. **{title}** ({source}) — {reason}")
    if len(rejected) > 20:
        lines.append(f"_…and {len(rejected) - 20} more rejected findings._")
    lines.append("")
    return lines


def build_markdown_report(output: dict[str, Any]) -> str:
    verified = output.get("verifiedFindings", [])
    rejected = output.get("rejectedFindings", [])
    needs_evidence = output.get("needsMoreEvidenceFindings", [])
    summary = output.get("metrics", {}).get("summary", {})
    severity_counts = _severity_counts(output)

    verified_count = summary.get("verifiedCount")
    if not isinstance(verified_count, int):
        verified_count = len(verified) if isinstance(verified, list) else 0
    rejected_count = summary.get("rejectedCount")
    if not isinstance(rejected_count, int):
        rejected_count = len(rejected) if isinstance(rejected, list) else 0
    needs_count = summary.get("needsEvidenceCount")
    if not isinstance(needs_count, int):
        needs_count = len(needs_evidence) if isinstance(needs_evidence, list) else 0

    lines = [
        "# Cyber Swarm Findings Report",
        "",
        "## Summary",
        "",
        f"- **Scan ID:** `{output.get('scanId', 'unknown')}`",
        f"- **Status:** {output.get('status', 'unknown')}",
        f"- **Started:** {output.get('startedAt', 'unknown')}",
        f"- **Completed:** {output.get('completedAt', 'unknown')}",
        f"- **Verified findings:** {verified_count}",
        f"- **Rejected findings:** {rejected_count}",
        f"- **Needs more evidence:** {needs_count}",
        "",
        "## Severity counts",
        "",
    ]

    if severity_counts:
        for severity in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(severity, 0)
            if count:
                lines.append(f"- **{severity}:** {count}")
    else:
        lines.append("_No verified findings to rank._")
    lines.append("")

    lines.extend(["## Verified findings", ""])
    if isinstance(verified, list) and verified:
        for index, finding in enumerate(verified, start=1):
            if isinstance(finding, dict):
                lines.extend(_format_verified_finding(index, finding))
    else:
        lines.extend(["_No verified findings in this run._", ""])

    lines.extend(["## Rejected findings summary", ""])
    if isinstance(rejected, list):
        lines.extend(_format_rejected_summary(rejected))
    else:
        lines.extend(["_No rejected findings._", ""])

    retrieval = output.get("metrics", {}).get("retrieval", {})
    selected_context = retrieval.get("selectedContext", []) if isinstance(retrieval, dict) else []
    if isinstance(selected_context, list) and selected_context:
        lines.extend(["## Retrieval sources", ""])
        for item in selected_context[:15]:
            if not isinstance(item, dict):
                continue
            source_path = item.get("sourcePath") or item.get("source_path") or "unknown"
            reason = item.get("reason", "")
            lines.append(f"- `{source_path}` — {reason}")
        if len(selected_context) > 15:
            lines.append(f"_…and {len(selected_context) - 15} more retrieval hits._")
        lines.append("")

    routed = output.get("metrics", {}).get("agents", {})
    if isinstance(routed, dict):
        specialists = routed.get("specialists", {})
        if isinstance(specialists, dict):
            skills: set[str] = set()
            for finding in verified if isinstance(verified, list) else []:
                if isinstance(finding, dict):
                    for skill in finding.get("selected_skills", []):
                        if isinstance(skill, str):
                            skills.add(skill)
            if skills:
                lines.extend(["## Skills used", ""])
                for skill in sorted(skills):
                    lines.append(f"- `{skill}`")
                lines.append("")

    lines.extend(
        [
            "---",
            "",
            "_Generated by Cyber Swarm. Review verified findings before acting on suggested fixes._",
            "",
        ]
    )

    return "\n".join(lines)


def write_markdown_report(json_path: str, output: dict[str, Any]) -> str:
    markdown_path = derive_markdown_path(json_path)
    content = build_markdown_report(output)
    with open(markdown_path, "w", encoding="utf-8") as handle:
        handle.write(content)
        if not content.endswith("\n"):
            handle.write("\n")
    return markdown_path
