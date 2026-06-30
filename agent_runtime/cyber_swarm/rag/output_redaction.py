"""Redact secrets from findings reports, evidence packs, and nested payloads."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from cyber_swarm.models.agents import EvidenceRef, VerifiedFinding
from cyber_swarm.rag.redaction import REDACTED_SECRET, redact_secrets


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    return redact_secrets(value)


def redact_evidence_ref(item: EvidenceRef) -> EvidenceRef:
    return replace(
        item,
        explanation=redact_secrets(item.explanation),
        snippet=redact_secrets(item.snippet) if item.snippet else item.snippet,
    )


def redact_verified_finding(finding: VerifiedFinding) -> VerifiedFinding:
    return replace(
        finding,
        title=redact_secrets(finding.title),
        claim=redact_secrets(finding.claim),
        impact_hypothesis=redact_secrets(finding.impact_hypothesis),
        attack_path=redact_secrets(finding.attack_path),
        evidence=[redact_evidence_ref(item) for item in finding.evidence],
        safe_reproduction=replace(
            finding.safe_reproduction,
            steps=[redact_secrets(step) for step in finding.safe_reproduction.steps],
            expected_result=redact_secrets(finding.safe_reproduction.expected_result),
            safety_notes=[redact_secrets(note) for note in finding.safe_reproduction.safety_notes],
        ),
    )


def redact_evidence_pack_dict(pack: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(pack)
    snippet = pack.get("snippet")
    if isinstance(snippet, str):
        redacted["snippet"] = redact_secrets(snippet)
    return redacted


def redact_output_payload(output: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(output)

    verified = output.get("verifiedFindings", [])
    if isinstance(verified, list):
        redacted["verifiedFindings"] = [
            _redact_finding_dict(item) if isinstance(item, dict) else item for item in verified
        ]

    rejected = output.get("rejectedFindings", [])
    if isinstance(rejected, list):
        redacted["rejectedFindings"] = [
            _redact_rejected_dict(item) if isinstance(item, dict) else item for item in rejected
        ]

    packs = output.get("evidencePacks", [])
    if isinstance(packs, list):
        redacted["evidencePacks"] = [
            redact_evidence_pack_dict(item) if isinstance(item, dict) else item for item in packs
        ]

    return redacted


def _redact_finding_dict(finding: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(finding)
    for key in ("title", "claim", "impact_hypothesis", "attack_path"):
        value = finding.get(key)
        if isinstance(value, str):
            redacted[key] = redact_secrets(value)

    evidence = finding.get("evidence", [])
    if isinstance(evidence, list):
        redacted["evidence"] = [_redact_evidence_dict(item) for item in evidence if isinstance(item, dict)]

    reproduction = finding.get("safe_reproduction")
    if isinstance(reproduction, dict):
        redacted["safe_reproduction"] = _redact_reproduction_dict(reproduction)

    return redacted


def _redact_rejected_dict(item: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(item)
    reason = item.get("reason")
    if isinstance(reason, str):
        redacted["reason"] = redact_secrets(reason)
    evidence = item.get("evidence", [])
    if isinstance(evidence, list):
        redacted["evidence"] = [_redact_evidence_dict(entry) for entry in evidence if isinstance(entry, dict)]
    return redacted


def _redact_evidence_dict(item: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(item)
    for key in ("explanation", "snippet"):
        value = item.get(key)
        if isinstance(value, str):
            redacted[key] = redact_secrets(value)
    return redacted


def _redact_reproduction_dict(reproduction: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(reproduction)
    steps = reproduction.get("steps", [])
    if isinstance(steps, list):
        redacted["steps"] = [redact_secrets(step) if isinstance(step, str) else step for step in steps]
    expected = reproduction.get("expected_result")
    if isinstance(expected, str):
        redacted["expected_result"] = redact_secrets(expected)
    notes = reproduction.get("safety_notes", [])
    if isinstance(notes, list):
        redacted["safety_notes"] = [redact_secrets(note) if isinstance(note, str) else note for note in notes]
    return redacted


__all__ = ["REDACTED_SECRET", "redact_output_payload", "redact_verified_finding", "redact_secrets"]
