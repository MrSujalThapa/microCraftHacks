"""Demo-readiness quality gate for verified findings."""

from __future__ import annotations

import re
from dataclasses import replace

from cyber_swarm.models.agents import AgentFindingDraft, VerifiedFinding

PUBLIC_ROUTE_PATHS = frozenset({"/", "/health", "/api/health", "/status", "/ping"})

_GENERIC_AUTH_GAP = re.compile(
    r"(?i)("
    r"(?:missing|lacks|without|no|not)\s+(?:[\w-]+\s+){0,4}"
    r"(?:auth(?:entication|orization)?|validation|credentials?|guard|middleware)|"
    r"unauthenticated|not enforced|not validated|"
    r"visible auth|visible validation|visible authorization|"
    r"missing visible auth|missing visible validation|"
    r"lacks auth dependency|lacks schema validation|"
    r"public health|health endpoint|health check|health route|"
    r"/health|/api/health|/ping|/status"
    r")"
)

from cyber_swarm.evidence.secret_packs import sensitive_exposure_match

_STATE_CHANGING = re.compile(r"(?i)\b(post|put|patch|delete|mutate|write|execute|invoke)\b")

_GET_HANDLER = re.compile(
    r"(?i)(@app\.get|@router\.get|router\.get\s*\(|\.get\s*\(|methods\s*=\s*\[\s*[\"']GET|async def get_|\bGET /)"
)

_HANDLER_GAP_TITLE = re.compile(
    r"(?i)handler lacks visible (auth(?:entication|orization)?|validation|auth dependency)"
)

_USER_CONTROLLED_INPUT = re.compile(
    r"(?i)(user[_-]?id|customer[_-]?id|account[_-]?id|owner[_-]?id|/{[^}]+}|path param|"
    r"query param|request\.body|request body|payload|upload|multipart|form data|"
    r"create|update|delete|insert|modify)"
)

_ROUTE_IN_TEXT = re.compile(r"(?i)(/api/[\w-]+|/health\b|/status\b|/ping\b)")


def normalize_route(route: str) -> str:
    cleaned = route.strip().lower()
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"
    return cleaned.rstrip("/") or "/"


def is_public_route(route: str) -> bool:
    return normalize_route(route) in PUBLIC_ROUTE_PATHS


def _routes_from_text(finding: VerifiedFinding | AgentFindingDraft) -> set[str]:
    routes: set[str] = set()
    text = _finding_text(finding)
    for match in _ROUTE_IN_TEXT.finditer(text):
        routes.add(normalize_route(match.group(1)))
    if re.search(r"(?i)\bhealth endpoint\b|\bhealth check\b|\bpublic health\b", text):
        routes.add("/health")
    return routes


def _collect_routes(finding: VerifiedFinding | AgentFindingDraft) -> set[str]:
    routes: set[str] = set()
    for surface in finding.affected_surfaces:
        if isinstance(surface, str) and surface.strip().startswith("/"):
            routes.add(normalize_route(surface))
    for item in finding.evidence:
        if item.route:
            routes.add(normalize_route(item.route))
    routes.update(_routes_from_text(finding))
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


def _is_readonly_get_handler(finding: VerifiedFinding | AgentFindingDraft) -> bool:
    text = _finding_text(finding)
    if _GET_HANDLER.search(text):
        return True
    if _HANDLER_GAP_TITLE.search(finding.title):
        return True
    for item in finding.evidence:
        snippet = item.snippet or ""
        if _GET_HANDLER.search(snippet):
            return True
        if item.route and _GENERIC_AUTH_GAP.search(item.explanation or ""):
            return True
    return False


def is_generic_readonly_get_finding(finding: VerifiedFinding | AgentFindingDraft) -> bool:
    if finding.vulnerability_class == "secret-exposure":
        return False

    text = _finding_text(finding)
    if not _GENERIC_AUTH_GAP.search(text):
        return False
    if not _is_readonly_get_handler(finding):
        return False

    exposure = _exposure_text(finding)
    if sensitive_exposure_match(exposure):
        return False
    if _STATE_CHANGING.search(text) and not _GENERIC_AUTH_GAP.search(finding.claim):
        return False
    if _USER_CONTROLLED_INPUT.search(text):
        return False
    return True


def is_generic_public_route_finding(finding: VerifiedFinding | AgentFindingDraft) -> bool:
    routes = _collect_routes(finding)
    if not routes:
        return False
    if not routes.issubset(PUBLIC_ROUTE_PATHS):
        return False

    text = _finding_text(finding)
    exposure = _exposure_text(finding)
    if sensitive_exposure_match(exposure):
        return False
    if _STATE_CHANGING.search(text) and not _GENERIC_AUTH_GAP.search(finding.claim):
        return False

    return _GENERIC_AUTH_GAP.search(text) is not None


def is_generic_demo_noise_finding(finding: VerifiedFinding | AgentFindingDraft) -> bool:
    return is_generic_public_route_finding(finding) or is_generic_readonly_get_finding(finding)


def assess_demo_quality(finding: VerifiedFinding) -> tuple[bool, str]:
    if is_generic_demo_noise_finding(finding):
        return (
            False,
            "Generic read-only route finding without sensitive exposure, user input, or side effects",
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
    if is_generic_readonly_get_finding(draft):
        return [
            "generic read-only GET route finding without sensitive exposure, user input, or side effects"
        ]
    return []
