"""Deduplicate verified findings by vulnerability class, surface, and root cause."""

from __future__ import annotations

import re
from dataclasses import replace

from cyber_swarm.models.agents import EvidenceRef, VerifiedFinding

_ACCESS_CONTROL_CLASSES = frozenset(
    {
        "broken-access-control",
        "api-abuse",
        "authorization-bypass",
        "idor",
    }
)


def _normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip().lower()


def _primary_surface(finding: VerifiedFinding) -> str:
    for surface in finding.affected_surfaces:
        if surface.startswith("/"):
            return surface.strip().lower()
    for path in finding.affected_files:
        if path:
            return _normalize_path(path)
    for item in finding.evidence:
        if item.route:
            return item.route.strip().lower()
        if item.path:
            return _normalize_path(item.path)
    return ""


def _claim_fingerprint(claim: str, vulnerability_class: str) -> str:
    words = re.findall(r"[a-z0-9]{4,}", claim.lower())
    significant = sorted(set(words))[:6]
    if not significant:
        return vulnerability_class.lower()
    return "|".join(significant)


def dedupe_key(finding: VerifiedFinding) -> tuple[str, str]:
    surface = _primary_surface(finding)
    if finding.vulnerability_class in _ACCESS_CONTROL_CLASSES and surface.startswith("/"):
        return (surface, "access-control")
    fingerprint = _claim_fingerprint(finding.claim, finding.vulnerability_class)
    return (surface, f"{finding.vulnerability_class.lower()}::{fingerprint}")


def _evidence_key(item: EvidenceRef) -> tuple[str, str | None, int | None, int | None]:
    return (
        item.type,
        _normalize_path(item.path) if item.path else None,
        item.line_start,
        item.line_end,
    )


def _merge_evidence(existing: list[EvidenceRef], incoming: list[EvidenceRef]) -> list[EvidenceRef]:
    merged = list(existing)
    seen = {_evidence_key(item) for item in existing}
    for item in incoming:
        key = _evidence_key(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _merge_unique(existing: list[str], incoming: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in [*existing, *incoming]:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _confidence_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(value, 0)


def merge_findings(primary: VerifiedFinding, duplicate: VerifiedFinding) -> VerifiedFinding:
    stronger = primary
    if _confidence_rank(duplicate.confidence) > _confidence_rank(primary.confidence):
        stronger = duplicate

    return replace(
        stronger,
        evidence=_merge_evidence(primary.evidence, duplicate.evidence),
        affected_surfaces=_merge_unique(primary.affected_surfaces, duplicate.affected_surfaces),
        affected_files=_merge_unique(primary.affected_files, duplicate.affected_files),
        contributing_agents=_merge_unique(primary.contributing_agents, duplicate.contributing_agents),
        contributing_specialists=_merge_unique(
            primary.contributing_specialists,
            duplicate.contributing_specialists,
        ),
        selected_skills=_merge_unique(primary.selected_skills, duplicate.selected_skills),
        retrieval_trace=_merge_unique(primary.retrieval_trace, duplicate.retrieval_trace),
        source_draft_ids=_merge_unique(primary.source_draft_ids, duplicate.source_draft_ids),
    )


def dedupe_verified_findings(findings: list[VerifiedFinding]) -> tuple[list[VerifiedFinding], int]:
    """Return deduplicated findings and the number of merged duplicates."""
    grouped: dict[tuple[str, str], VerifiedFinding] = {}
    merged_count = 0

    for finding in findings:
        key = dedupe_key(finding)
        if key not in grouped:
            grouped[key] = finding
            continue
        grouped[key] = merge_findings(grouped[key], finding)
        merged_count += 1

    return list(grouped.values()), merged_count
