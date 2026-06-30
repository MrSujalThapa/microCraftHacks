"""Render demo-ready Markdown findings reports."""

from __future__ import annotations

from typing import Any

from cyber_swarm.rag.redaction import contains_raw_secret, redact_secrets


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


def _project_root(output: dict[str, Any]) -> str | None:
    load_input = output.get("metrics", {}).get("load_input", {})
    if isinstance(load_input, dict):
        root = load_input.get("projectRoot")
        if isinstance(root, str) and root.strip():
            return root
    return None


def _is_demo_ready_dict(finding: dict[str, Any]) -> bool:
    if finding.get("demo_ready") is True:
        return True
    if finding.get("demo_ready") is False:
        return False
    return finding.get("vulnerability_class") == "secret-exposure"


def _format_evidence(
    evidence: list[dict[str, Any]],
    evidence_packs: list[dict[str, Any]] | None = None,
) -> list[str]:
    lines: list[str] = []
    pack_by_id = {
        pack.get("id"): pack
        for pack in (evidence_packs or [])
        if isinstance(pack, dict) and pack.get("id")
    }
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
        explanation = redact_secrets(str(item.get("explanation", "")))
        evidence_type = item.get("type", "evidence")
        lines.append(f"- **[{evidence_type}]** {location} — {explanation}")
        snippet = item.get("snippet")
        if not isinstance(snippet, str) or not snippet.strip():
            pack = pack_by_id.get(item.get("evidence_pack_id"))
            if isinstance(pack, dict):
                snippet = pack.get("snippet")
        if isinstance(snippet, str) and snippet.strip():
            redacted_snippet = redact_secrets(snippet.strip())
            lines.append("  ```")
            for snippet_line in redacted_snippet.splitlines():
                lines.append(f"  {snippet_line}")
            lines.append("  ```")
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
                lines.append(f"  1. {redact_secrets(step)}")
    expected = reproduction.get("expected_result")
    if isinstance(expected, str) and expected:
        lines.append(f"- **Expected result:** {redact_secrets(expected)}")
    notes = reproduction.get("safety_notes", [])
    if isinstance(notes, list) and notes:
        lines.append("- **Safety notes:**")
        for note in notes:
            if isinstance(note, str):
                lines.append(f"  - {redact_secrets(note)}")
    return lines


def _format_fix_plan(finding: dict[str, Any]) -> list[str]:
    vuln_class = str(finding.get("vulnerability_class", "unknown"))
    lines = [
        f"- Address `{finding.get('id', 'unknown')}` with concrete remediation.",
        f"- Class: `{vuln_class}` — run `swarm fix {finding.get('id', '<finding-id>')}` for step-by-step guidance.",
    ]
    if vuln_class == "secret-exposure":
        lines.extend(
            [
                "- Purge committed secrets from git history; load live values from environment or a secret manager.",
                "- Keep `.env.example` with placeholder values only; never commit `.env`.",
            ]
        )
    elif vuln_class == "broken-access-control":
        lines.append("- Enforce authentication/authorization before sensitive route handlers execute.")
    return lines


def _format_verified_finding(
    index: int,
    finding: dict[str, Any],
    evidence_packs: list[dict[str, Any]] | None = None,
) -> list[str]:
    title = redact_secrets(str(finding.get("title", "Untitled finding")))
    lines = [
        f"### {index}. {title}",
        "",
        f"- **ID:** `{finding.get('id', 'unknown')}`",
        f"- **Severity:** {finding.get('severity', 'unknown')}  "
        f"**Confidence:** {finding.get('confidence', 'unknown')}",
        f"- **Class:** `{finding.get('vulnerability_class', 'unknown')}`",
        f"- **Demo ready:** {'yes' if _is_demo_ready_dict(finding) else 'no'}"
        + (f" — {finding.get('demo_reason')}" if finding.get('demo_reason') else ""),
        "",
        "**Claim**",
        "",
        redact_secrets(str(finding.get("claim", ""))),
        "",
        "**Impact**",
        "",
        redact_secrets(str(finding.get("impact_hypothesis", ""))),
        "",
        "**Attack path**",
        "",
        redact_secrets(str(finding.get("attack_path", ""))),
        "",
    ]

    graph_path = finding.get("graph_path")
    if isinstance(graph_path, dict):
        lines.extend(["**Graph path**", ""])
        if graph_path.get("path_description"):
            lines.append(redact_secrets(str(graph_path["path_description"])))
        if graph_path.get("trust_boundary_crossed"):
            lines.append(f"- Trust boundary: `{graph_path['trust_boundary_crossed']}`")
        if graph_path.get("missing_guard"):
            lines.append(f"- Missing guard: `{graph_path['missing_guard']}`")
        lines.append("")

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
    lines.extend(["**Evidence (redacted)**", ""])
    if isinstance(evidence, list):
        lines.extend(_format_evidence(evidence, evidence_packs) or ["- _No evidence recorded._"])
    else:
        lines.append("- _No evidence recorded._")
    lines.append("")

    reproduction = finding.get("safe_reproduction", {})
    lines.extend(["**Safe reproduction**", ""])
    lines.extend(_format_reproduction(reproduction if isinstance(reproduction, dict) else {}))
    lines.append("")

    lines.extend(["**Concrete fix plan**", ""])
    lines.extend(_format_fix_plan(finding))
    lines.append("")

    qa = finding.get("qa_comparison")
    if isinstance(qa, dict):
        lines.extend(["**Why QA tests may miss this**", ""])
        if qa.get("why_qa_may_miss"):
            lines.append(redact_secrets(str(qa["why_qa_may_miss"])))
        lines.append("")
        lines.extend(["**Why code review may miss this**", ""])
        if qa.get("why_review_may_miss"):
            lines.append(redact_secrets(str(qa["why_review_may_miss"])))
        lines.append("")
        lines.extend(["**Suggested regression test**", ""])
        if qa.get("suggested_regression_test"):
            lines.append(redact_secrets(str(qa["suggested_regression_test"])))
        lines.append("")

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
                lines.append(f"- Weighted score: `{total:.3f}`")
            lines.append("")

    specialists = finding.get("contributing_specialists", [])
    if isinstance(specialists, list) and specialists:
        lines.extend(["**Contributing specialists**", ""])
        for name in specialists:
            if isinstance(name, str):
                lines.append(f"- `{name}`")
        lines.append("")

    playbooks = finding.get("selected_skills", [])
    if isinstance(playbooks, list) and playbooks:
        lines.extend(["**Playbooks used**", ""])
        for skill in playbooks:
            if isinstance(skill, str):
                lines.append(f"- `{skill}`")
        lines.append("")

    return lines


def _format_rejected_summary(rejected: list[Any], title: str = "Rejected findings") -> list[str]:
    if not rejected:
        return [f"_No {title.lower()}._", ""]

    lines = [f"**Total {title.lower()}:** {len(rejected)}", ""]
    for index, item in enumerate(rejected[:20], start=1):
        if not isinstance(item, dict):
            continue
        item_title = redact_secrets(str(item.get("title") or item.get("draft_id") or "Rejected draft"))
        reason = redact_secrets(str(item.get("reason", "No reason recorded")))
        source = item.get("source", "unknown")
        lines.append(f"{index}. **{item_title}** ({source}) — {reason}")
    if len(rejected) > 20:
        lines.append(f"_…and {len(rejected) - 20} more {title.lower()}._")
    lines.append("")
    return lines


def _demo_ready_findings(verified: list[Any]) -> list[dict[str, Any]]:
    ready: list[dict[str, Any]] = []
    for item in verified:
        if isinstance(item, dict) and _is_demo_ready_dict(item):
            ready.append(item)
    return ready


def _downgraded_findings(verified: list[Any], demo_ready: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ready_ids = {item.get("id") for item in demo_ready}
    return [
        item
        for item in verified
        if isinstance(item, dict) and item.get("id") not in ready_ids
    ]


def build_markdown_report(output: dict[str, Any]) -> str:
    verified = output.get("verifiedFindings", [])
    rejected = output.get("rejectedFindings", [])
    needs_evidence = output.get("needsMoreEvidenceFindings", [])
    evidence_packs = output.get("evidencePacks", [])
    summary = output.get("metrics", {}).get("summary", {})
    activation = output.get("metrics", {}).get("activation", {})
    load_input = output.get("metrics", {}).get("load_input", {})
    runtime = output.get("metrics", {}).get("runtime", {})
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

    verified_list = verified if isinstance(verified, list) else []
    demo_ready = _demo_ready_findings(verified_list)
    demo_ready_count = summary.get("demoReadyCount")
    if not isinstance(demo_ready_count, int):
        demo_ready_count = len(demo_ready)
    downgraded = _downgraded_findings(verified_list, demo_ready)

    project_root = _project_root(output)
    playbooks_routed = activation.get("skillsRouted", 0) if isinstance(activation, dict) else 0
    specialists_run = activation.get("agentsRun", 0) if isinstance(activation, dict) else 0
    specialist_types = activation.get("agentTypes", []) if isinstance(activation, dict) else []

    executive = (
        "Cyber Swarm completed an authorized static security review. "
        f"This run verified **{verified_count}** finding(s), rejected **{rejected_count}**, "
        f"and surfaced **{demo_ready_count}** demo-ready item(s) suitable for live judging."
    )

    lines = [
        "# Cyber Swarm Findings Report",
        "",
        "## Executive summary",
        "",
        executive,
        "",
        "## Target / scan summary",
        "",
        f"- **Scan ID:** `{output.get('scanId', 'unknown')}`",
        f"- **Status:** {output.get('status', 'unknown')}",
        f"- **Target repo:** `{project_root or 'unknown'}`",
        f"- **Started:** {output.get('startedAt', 'unknown')}",
        f"- **Completed:** {output.get('completedAt', 'unknown')}",
        f"- **Verified findings:** {verified_count}",
        f"- **Demo-ready findings:** {demo_ready_count}",
        f"- **Rejected findings:** {rejected_count}",
        f"- **Needs more evidence:** {needs_count}",
        "",
    ]

    if isinstance(runtime, dict) and runtime:
        cache = runtime.get("cache", {})
        lines.append(
            f"- **Runtime:** provider `{runtime.get('provider', 'unknown')}`  "
            f"model `{runtime.get('model', 'unknown')}`  "
            f"mode `{runtime.get('mode', 'full')}`  "
            f"elapsed `{runtime.get('elapsedMs', 'n/a')}` ms"
        )
        if isinstance(cache, dict) and cache.get("scanHash"):
            lines.append(
                f"- **Cache:** {'hit' if cache.get('hit') else 'miss'} (`{cache.get('scanHash')}`)"
            )
        lines.append("")

    if isinstance(load_input, dict) and load_input.get("scanReportPath"):
        lines.append(f"- **Scan report:** `{load_input.get('scanReportPath')}`")
        lines.append("")

    lines.extend(["## Severity counts", ""])
    if severity_counts:
        for severity in ("critical", "high", "medium", "low", "info"):
            count = severity_counts.get(severity, 0)
            if count:
                lines.append(f"- **{severity}:** {count}")
    else:
        lines.append("_No verified findings to rank._")
    lines.append("")

    lines.extend(
        [
            "## Routed playbooks",
            "",
            f"- **Playbooks routed:** {playbooks_routed}",
            "",
        ]
    )
    playbook_names: set[str] = set()
    for finding in verified_list:
        if isinstance(finding, dict):
            for skill in finding.get("selected_skills", []):
                if isinstance(skill, str):
                    playbook_names.add(skill)
    if playbook_names:
        for skill in sorted(playbook_names):
            lines.append(f"- `{skill}`")
    else:
        lines.append("_No playbooks recorded on verified findings._")
    lines.append("")

    lines.extend(["## Activated specialists", ""])
    if isinstance(specialist_types, list) and specialist_types:
        lines.append(f"- **Specialists run:** {specialists_run}")
        for name in specialist_types:
            if isinstance(name, str):
                lines.append(f"- `{name}`")
    else:
        lines.append("_No specialist activation recorded._")
    lines.append("")

    lines.extend(["## Demo-ready findings", ""])
    if demo_ready:
        for index, finding in enumerate(demo_ready, start=1):
            lines.extend(
                _format_verified_finding(
                    index,
                    finding,
                    evidence_packs if isinstance(evidence_packs, list) else None,
                )
            )
    else:
        lines.extend(["_No demo-ready findings in this run._", ""])

    lines.extend(["## Rejected / downgraded findings", ""])
    if isinstance(rejected, list) and rejected:
        lines.extend(_format_rejected_summary(rejected, "Rejected findings"))
    if downgraded:
        lines.append("**Downgraded (verified but not demo-ready)**")
        lines.append("")
        for index, item in enumerate(downgraded[:20], start=1):
            title = redact_secrets(str(item.get("title", item.get("id", "finding"))))
            reason = item.get("demo_reason") or "Not suitable for live demo"
            lines.append(f"{index}. **{title}** — {reason}")
        if len(downgraded) > 20:
            lines.append(f"_…and {len(downgraded) - 20} more downgraded findings._")
        lines.append("")
    elif not rejected:
        lines.extend(["_No rejected or downgraded findings._", ""])

    lines.extend(["## All verified findings", ""])
    if verified_list:
        for index, finding in enumerate(verified_list, start=1):
            if isinstance(finding, dict):
                lines.extend(
                    _format_verified_finding(
                        index,
                        finding,
                        evidence_packs if isinstance(evidence_packs, list) else None,
                    )
                )
    else:
        lines.extend(["_No verified findings in this run._", ""])

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

    lines.extend(
        [
            "---",
            "",
            "_Generated by Cyber Swarm. All evidence snippets are redacted. "
            "Review verified findings before acting on suggested fixes._",
            "",
        ]
    )

    content = "\n".join(lines)
    if contains_raw_secret(content):
        content = redact_secrets(content)
    return content


def write_markdown_report(json_path: str, output: dict[str, Any]) -> str:
    markdown_path = derive_markdown_path(json_path)
    content = build_markdown_report(output)
    with open(markdown_path, "w", encoding="utf-8") as handle:
        handle.write(content)
        if not content.endswith("\n"):
            handle.write("\n")
    return markdown_path
