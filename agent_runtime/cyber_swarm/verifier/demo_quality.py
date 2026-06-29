"""Demo-readiness quality gate for verified findings."""

from __future__ import annotations

import re
from dataclasses import replace

from cyber_swarm.models.agents import AgentFindingDraft, VerifiedFinding

PUBLIC_ROUTE_PATHS = frozenset({"/", "/health", "/api/health", "/status", "/ping"})

_GENERIC_AUTH_GAP = re.compile(
    r"(?i)("
    r"missing auth|lacks auth|without auth|no auth|unauthenticated|"
    r"missing validation|lacks validation|without validation|no validation|"
    r"not enforced|not validated|public health|health endpoint|health check|"
    r"health route|/health|/api/health|/ping|/status"
    r")"
)

_SENSITIVE_INDICATORS = re.compile(
    r"(?i)("
    r"credential|secret|password|token|api[_-]?key|private[_-]?key|"
    r"pii|ssn|credit.?card|user.?data|email.?address|"
    r"database.?url|connection.?string|internal.?infra|stack.?trace|"
    r"debug.?info|env.?var|service.?role|admin.?key|"
    r"side.?effect|tool.?call|"
    r"llm|openai|anthropic|embedding|prompt.?injection|"
    r"supabase|postgres|redis|aws|stripe"
    r")"
)

_STATE_CHANGING = re.compile(r"(?i)\b(post|put|patch|delete|mutate|write|execute|invoke)\b")


def normalize_route(route: str) -> str:
    cleaned = route.strip().lower()
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned.rstrip("/") or "/"


def is_public_route(route: str) -> bool:
    return normalize_route(route) in PUBLIC_ROUTE_PATHS


def _collect_routes(finding: VerifiedFinding | AgentFindingDraft) -> set[str]:
    routes: set[str] = set()
    for surface in finding.affected_surfaces:
        if isinstance(surface, str) and surface.strip().startswith("/"):
            routes.add(normalize_route(surface))
    for item in finding.evidence:
        if item.route:
            routes.add(normalize_route(item.route))
    return routes


def _finding_text(finding: VerifiedFinding | AgentFindingDraft) -> str:
    parts = [
        finding.title,
        finding.claim,
        getattr(finding, "impact_hypothesis", ""),
    ]
    for item in finding.evidence:
        parts.append(item.explanation)
        if item.snippet:
            parts.append(item.snippet)
    return " ".join(part for part in parts if part)


def _exposure_text(finding: VerifiedFinding | AgentFindingDraft) -> str:
    """Text that indicates sensitive data is actually exposed (not merely missing auth)."""
    parts = [_finding_text(finding), getattr(finding, "attack_path", "")]
    blob = " ".join(part for part in parts if part)
    negative_auth_context = re.compile(
        r"(?i)\b(without|missing|lacks|no)\s+(auth(entication)?|credentials?|validation)\b"
    )
    return negative_auth_context.sub("", blob)


def is_generic_public_route_finding(finding: VerifiedFinding | AgentFindingDraft) -> bool:
    routes = _collect_routes(finding)
    if not routes:
        return False
    if not routes.issubset(PUBLIC_ROUTE_PATHS):
        return False

    text = _finding_text(finding)
    exposure = _exposure_text(finding)
    if _SENSITIVE_INDICATORS.search(exposure):
        return False
    if _STATE_CHANGING.search(text) and not _GENERIC_AUTH_GAP.search(finding.claim):
        return False

    return _GENERIC_AUTH_GAP.search(text) is not None


def assess_demo_quality(finding: VerifiedFinding) -> tuple[bool, str]:
    if is_generic_public_route_finding(finding):
        return (
            False,
            "Generic public health/root route finding without sensitive exposure or side effects",
        )

    if finding.vulnerability_class == "secret-exposure":
        return True, "Verified secret exposure with redacted evidence"

    if finding.confidence == "high" and finding.ranking_rationale.total_score >= 0.5:
        return True, "High-confidence verified finding with strong ranking score"

    if finding.confidence in {"high", "medium"}:
        return True, "Verified finding suitable for live demo"

    return False, "Verified but lower confidence; review before demo"


def annotate_demo_quality(finding: VerifiedFinding) -> VerifiedFinding:
    demo_ready, demo_reason = assess_demo_quality(finding)
    return replace(finding, demo_ready=demo_ready, demo_reason=demo_reason)


def public_route_verification_failures(draft: AgentFindingDraft) -> list[str]:
    if is_generic_public_route_finding(draft):
        return [
            "generic public health/root route finding without sensitive data, credentials, or side effects"
        ]
    return []
