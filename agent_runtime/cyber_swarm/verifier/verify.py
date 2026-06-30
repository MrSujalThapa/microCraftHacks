"""Deterministic draft finding verification (no runtime probes, no LLM)."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from cyber_swarm.agents.specialists.base import is_vague_draft
from cyber_swarm.models.agents import (
    AgentFindingDraft,
    EvidenceRef,
    NeedsMoreEvidenceFinding,
    QaComparison,
    RankingRationale,
    VerifiedFinding,
    VerificationStatus,
    VerifierRejectedFinding,
)
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import packs_by_id
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.rag.redaction import contains_raw_secret, redact_secrets
from cyber_swarm.rag.output_redaction import redact_evidence_ref
from cyber_swarm.verifier.demo_quality import public_route_verification_failures
from cyber_swarm.verifier.graph_strict import graph_backed_evidence_failures
from cyber_swarm.verifier.strict import (
    affected_path_failures,
    concrete_anchor_failures,
    generic_evidence_failures,
    hedge_language_failures,
    is_valid_repo_file_path,
    normalize_path,
    reproduction_failures,
    specific_issue_failures,
    split_surfaces_and_files,
)

_STOPWORDS = frozenset(
    {
        "that",
        "this",
        "with",
        "from",
        "have",
        "should",
        "before",
        "after",
        "into",
        "without",
        "static",
        "evidence",
        "shows",
        "could",
        "would",
        "their",
        "there",
        "which",
        "about",
        "through",
        "review",
        "identify",
        "missing",
    }
)

_UNREDACTED_SECRET = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*(?!<?REDACTED_SECRET>?)\S+"
)


def _redact_draft_evidence(draft: AgentFindingDraft) -> AgentFindingDraft:
    return replace(
        draft,
        title=redact_secrets(draft.title),
        claim=redact_secrets(draft.claim),
        impact_hypothesis=redact_secrets(draft.impact_hypothesis),
        attack_path=redact_secrets(draft.attack_path),
        evidence=[redact_evidence_ref(item) for item in draft.evidence],
        safe_reproduction=replace(
            draft.safe_reproduction,
            steps=[redact_secrets(step) for step in draft.safe_reproduction.steps],
            expected_result=redact_secrets(draft.safe_reproduction.expected_result),
            safety_notes=[redact_secrets(note) for note in draft.safe_reproduction.safety_notes],
        ),
    )


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    verified: VerifiedFinding | None = None
    rejected: VerifierRejectedFinding | None = None
    needs_evidence: NeedsMoreEvidenceFinding | None = None


def _inventory_paths(scan_report: dict) -> set[str]:
    inventory = scan_report.get("inventory", {})
    files = inventory.get("files", []) if isinstance(inventory, dict) else []
    return {
        normalize_path(item["path"])
        for item in files
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }


def _known_routes(scan_report: dict) -> set[str]:
    surfaces = scan_report.get("surfaces", {})
    if not isinstance(surfaces, dict):
        return set()
    routes: set[str] = set()
    for key in ("routes", "api"):
        items = surfaces.get(key, [])
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                routes.add(item["path"].strip().lower())
    return routes


def _context_paths(context_paths: set[str]) -> set[str]:
    return {normalize_path(path) for path in context_paths}


def _claim_tokens(claim: str) -> set[str]:
    words = re.findall(r"[a-z0-9]{4,}", claim.lower())
    return {word for word in words if word not in _STOPWORDS}


def _evidence_text(evidence: list[EvidenceRef]) -> str:
    parts: list[str] = []
    for item in evidence:
        parts.append(item.explanation.lower())
        if item.snippet:
            parts.append(item.snippet.lower())
        if item.path:
            parts.append(item.path.lower())
        if item.route:
            parts.append(item.route.lower())
    return " ".join(parts)


def _claim_matches_evidence(claim: str, evidence: list[EvidenceRef]) -> tuple[bool, float]:
    tokens = _claim_tokens(claim)
    if not tokens:
        return False, 0.0
    haystack = _evidence_text(evidence)
    if not haystack.strip():
        return False, 0.0
    matches = sum(1 for token in tokens if token in haystack)
    ratio = matches / len(tokens)
    return ratio >= 0.25, ratio


def _secrets_redacted(evidence: list[EvidenceRef]) -> tuple[bool, list[str]]:
    failures: list[str] = []
    for item in evidence:
        for field_name, value in (
            ("snippet", item.snippet or ""),
            ("explanation", item.explanation or ""),
        ):
            if contains_raw_secret(value):
                failures.append(f"unredacted secret in evidence {field_name}: {item.path or item.type}")
    return len(failures) == 0, failures


def _safe_reproduction_valid(draft: AgentFindingDraft) -> tuple[bool, list[str]]:
    repro = draft.safe_reproduction
    failures: list[str] = []
    if not repro.steps:
        failures.append("safe reproduction missing steps")
    if not repro.expected_result.strip():
        failures.append("safe reproduction missing expected result")
    return len(failures) == 0, failures


def _surface_exists(
    draft: AgentFindingDraft,
    inventory: set[str],
    routes: set[str],
    context: set[str],
) -> tuple[bool, list[str]]:
    failures: list[str] = []
    known = inventory | context

    file_hits = 0
    for item in draft.evidence:
        if item.path and normalize_path(item.path) in known:
            file_hits += 1
    for path in draft.affected_surfaces:
        normalized = normalize_path(path)
        if normalized in known or path.strip().lower() in routes:
            file_hits += 1

    route_hits = sum(
        1
        for surface in draft.affected_surfaces
        if surface.strip().lower() in routes
    )
    for item in draft.evidence:
        if item.route and item.route.strip().lower() in routes:
            route_hits += 1

    if file_hits == 0 and route_hits == 0:
        failures.append("affected files/routes not found in scan inventory or context")
    return len(failures) == 0, failures


def _placeholder_ranking() -> RankingRationale:
    return RankingRationale(
        impact=0.0,
        exploitability=0.0,
        confidence=0.0,
        surface_sensitivity=0.0,
        verification_strength=0.0,
        mock_destructive_potential=0.0,
        total_score=0.0,
        factors=["pending risk ranking"],
    )


def _draft_to_verified(
    draft: AgentFindingDraft,
    inventory: set[str],
    routes: set[str],
) -> VerifiedFinding:
    surfaces, files = split_surfaces_and_files(draft, inventory, routes)
    confidence: str = draft.confidence
    if confidence == "high" and not any(item.line_start is not None for item in draft.evidence):
        confidence = "medium"

    return VerifiedFinding(
        id=f"verified-{draft.id}",
        title=draft.title,
        vulnerability_class=draft.vulnerability_class,
        claim=draft.claim,
        affected_surfaces=surfaces,
        affected_files=files,
        evidence=list(draft.evidence),
        impact_hypothesis=draft.impact_hypothesis,
        attack_path=draft.attack_path,
        safe_reproduction=draft.safe_reproduction,
        confidence=confidence,  # type: ignore[arg-type]
        severity="medium",
        ranking_rationale=_placeholder_ranking(),
        contributing_agents=[draft.agent_type],
        contributing_specialists=[draft.specialist],
        selected_skills=list(draft.selected_skills),
        retrieval_trace=list(draft.retrieval_trace),
        source_draft_ids=[draft.id],
        graph_path=draft.graph_path,
        qa_comparison=draft.qa_comparison,
    )


def _evidence_pack_failures(
    draft: AgentFindingDraft,
    pack_index: dict[str, EvidencePack],
) -> list[str]:
    failures: list[str] = []
    file_evidence = [item for item in draft.evidence if item.type != "skill"]

    for item in file_evidence:
        if not item.evidence_pack_id:
            failures.append("evidence missing evidence_pack_id")
            continue
        pack = pack_index.get(item.evidence_pack_id)
        if pack is None:
            failures.append(f"unknown evidence pack id: {item.evidence_pack_id}")
            continue
        if item.path and normalize_path(item.path) != normalize_path(pack.path):
            failures.append(f"evidence path mismatch for pack {item.evidence_pack_id}")
        if item.line_start is not None and item.line_start != pack.line_start:
            failures.append(f"evidence line_start mismatch for pack {item.evidence_pack_id}")
        if item.line_end is not None and item.line_end != pack.line_end:
            failures.append(f"evidence line_end mismatch for pack {item.evidence_pack_id}")
        if item.snippet and pack.snippet:
            item_snippet = redact_secrets(item.snippet.strip())
            pack_snippet = redact_secrets(pack.snippet.strip())
            if (
                item_snippet != pack_snippet
                and item_snippet not in pack_snippet
                and pack_snippet not in item_snippet
            ):
                failures.append(f"evidence snippet mismatch for pack {item.evidence_pack_id}")

    return failures


def verify_draft(
    draft: AgentFindingDraft,
    scan_report: dict,
    *,
    context_paths: set[str] | None = None,
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> VerificationResult:
    """Verify a single draft finding against scan evidence and safety rules."""
    draft = _redact_draft_evidence(draft)
    inventory = _inventory_paths(scan_report)
    routes = _known_routes(scan_report)
    context = _context_paths(context_paths or set())
    pack_index = packs_by_id(evidence_packs or [])

    failed: list[str] = []
    needs_more: list[str] = []

    if not draft.evidence:
        failed.append("missing evidence refs")

    vague, vague_missing = is_vague_draft(draft)
    if vague:
        failed.extend(vague_missing)

    failed.extend(hedge_language_failures(draft))
    failed.extend(generic_evidence_failures(draft))
    failed.extend(concrete_anchor_failures(draft))
    failed.extend(specific_issue_failures(draft))
    failed.extend(affected_path_failures(draft, inventory, routes))
    failed.extend(_evidence_pack_failures(draft, pack_index))
    failed.extend(public_route_verification_failures(draft))
    failed.extend(graph_backed_evidence_failures(draft, attack_graph))

    surfaces, files = split_surfaces_and_files(draft, inventory, routes)
    if not files:
        failed.append("no valid repo file paths in affected files or evidence")
    failed.extend(reproduction_failures(draft, files))

    repro_ok, repro_failures = _safe_reproduction_valid(draft)
    if not repro_ok:
        failed.extend(repro_failures)

    redacted_ok, redaction_failures = _secrets_redacted(draft.evidence)
    if not redacted_ok:
        failed.extend(redaction_failures)

    surface_ok, surface_failures = _surface_exists(draft, inventory, routes, context)
    if not surface_ok:
        file_evidence = [item for item in draft.evidence if item.type == "file" and item.path]
        if file_evidence:
            needs_more.extend(surface_failures)
        else:
            failed.extend(surface_failures)

    claim_ok, claim_ratio = _claim_matches_evidence(draft.claim, draft.evidence)
    if not claim_ok:
        if draft.evidence and claim_ratio > 0:
            needs_more.append("claim only partially supported by evidence")
        else:
            failed.append("claim does not match evidence")

    skill_only = draft.evidence and all(item.type == "skill" for item in draft.evidence)
    if skill_only:
        needs_more.append("only skill references; missing project file evidence")

    for item in draft.evidence:
        if item.path and not is_valid_repo_file_path(item.path, inventory | context):
            if item.type != "skill":
                failed.append(f"evidence path is not a valid repo file: {item.path}")

    if failed:
        return VerificationResult(
            status="rejected",
            rejected=VerifierRejectedFinding(
                draft_id=draft.id,
                title=draft.title,
                reason="; ".join(failed),
                failed_checks=failed,
                evidence=list(draft.evidence),
            ),
        )

    if needs_more:
        return VerificationResult(
            status="needs_more_evidence",
            needs_evidence=NeedsMoreEvidenceFinding(
                draft_id=draft.id,
                title=draft.title,
                reason="; ".join(needs_more),
                missing_evidence=needs_more,
            ),
        )

    return VerificationResult(
        status="verified",
        verified=_draft_to_verified(draft, inventory, routes),
    )


def redact_verified_finding(finding: VerifiedFinding) -> VerifiedFinding:
    from cyber_swarm.rag.output_redaction import redact_verified_finding as _redact

    return _redact(finding)


def verify_drafts(
    drafts: list[AgentFindingDraft],
    scan_report: dict,
    *,
    context_paths: set[str] | None = None,
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> tuple[list[VerifiedFinding], list[VerifierRejectedFinding], list[NeedsMoreEvidenceFinding]]:
    verified: list[VerifiedFinding] = []
    rejected: list[VerifierRejectedFinding] = []
    needs_evidence: list[NeedsMoreEvidenceFinding] = []

    for draft in drafts:
        result = verify_draft(
            draft,
            scan_report,
            context_paths=context_paths,
            evidence_packs=evidence_packs,
            attack_graph=attack_graph,
        )
        if result.status == "verified" and result.verified is not None:
            verified.append(result.verified)
        elif result.status == "rejected" and result.rejected is not None:
            rejected.append(result.rejected)
        elif result.status == "needs_more_evidence" and result.needs_evidence is not None:
            needs_evidence.append(result.needs_evidence)

    return verified, rejected, needs_evidence
