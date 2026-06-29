"""Evidence-strict rules for verified findings."""

from __future__ import annotations

import re

from cyber_swarm.models.agents import AgentFindingDraft, EvidenceRef

_HEDGE_LANGUAGE = re.compile(
    r"(?i)\b("
    r"potential|possible|may|might|could|should check|needs review|review needed|"
    r"should review|requires review|needs further|further review|appears to|seems to"
    r")\b"
)

_GENERIC_EVIDENCE = re.compile(
    r"(?i)("
    r"supports?\s+(review|static|analysis|abuse|access-control)|"
    r"security[- ]relevant|"
    r"document routes|identify routes|"
    r"inspect (the )?(identified )?(files|routes|handlers)|"
    r"review (the )?(identified )?(files|routes|handlers|code)|"
    r"map protected routes|"
    r"check for schema|"
    r"without visible|"
    r"that should enforce|"
    r"that should not contain"
    r")"
)

_CODE_ELEMENT = re.compile(
    r"(?i)("
    r"\bfunction\b|\bdef\s+\w+|class\s+\w+|"
    r"@app\.(get|post|put|patch|delete|route)|router\.(get|post)|"
    r"\bmiddleware\b|\bguard\b|requireAuth|get_current_user|Depends\(|"
    r"validate|schema|handler|endpoint|createClient|useSession|"
    r"API_KEY|SECRET|password|token\s*="
    r")"
)

_ABSTRACT_SURFACE = re.compile(
    r"(?i)(<->|<|>|frontend|backend|trust boundary|service boundary|microservice)"
)

_VALID_PATH = re.compile(
    r"^(?:[\w.-]+/)+[\w.-]+\.(?:ts|tsx|js|jsx|py|json|yaml|yml|toml|md)$|^\.env[\w.-]*$",
    re.IGNORECASE,
)

_ISSUE_MARKERS = re.compile(
    r"(?i)("
    r"missing| lacks |without |not enforced|not validated|unauthenticated|"
    r"no auth|no validation|fails to|does not |absent |bypass|exposed|hardcoded|"
    r" lacks\b|omit|skipped|never calls"
    r")"
)


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip().lower()


def is_valid_repo_file_path(path: str, inventory: set[str]) -> bool:
    cleaned = path.strip()
    if not cleaned or " " in cleaned:
        return False
    normalized = normalize_path(cleaned)
    if normalized in inventory:
        return True
    if normalized.startswith(".env"):
        return True
    if _VALID_PATH.match(normalized):
        return True
    if _ABSTRACT_SURFACE.search(cleaned):
        return False
    return False


def is_route_surface(value: str, routes: set[str]) -> bool:
    cleaned = value.strip()
    return cleaned.startswith("/") or cleaned.lower() in routes


def hedge_language_failures(draft: AgentFindingDraft) -> list[str]:
    failures: list[str] = []
    if draft.title.strip().lower().startswith("potential"):
        failures.append("title uses Potential prefix")
    for label, text in (("title", draft.title), ("claim", draft.claim)):
        if _HEDGE_LANGUAGE.search(text):
            failures.append(f"{label} uses non-conclusive language (potential/possible/may/could/review)")
    return failures


def generic_evidence_failures(draft: AgentFindingDraft) -> list[str]:
    failures: list[str] = []
    file_evidence = [item for item in draft.evidence if item.type != "skill"]
    if not file_evidence:
        failures.append("missing file-level evidence")
        return failures

    for item in file_evidence:
        explanation = item.explanation.strip()
        if not explanation:
            failures.append("evidence explanation is empty")
            continue
        if item.evidence_pack_id and item.line_start is not None and item.path:
            continue
        if _GENERIC_EVIDENCE.search(explanation):
            failures.append(f"evidence only states file is review-relevant: {explanation[:96]}")
        if len(explanation) < 28:
            failures.append(f"evidence explanation too generic: {explanation[:96]}")
    return failures


def concrete_anchor_failures(draft: AgentFindingDraft) -> list[str]:
    failures: list[str] = []
    anchors = 0
    for item in draft.evidence:
        if item.type == "skill":
            continue
        blob = " ".join(
            part
            for part in (item.snippet or "", item.explanation or "", item.path or "")
            if part
        )
        if item.line_start is not None and item.path:
            anchors += 1
            continue
        if _CODE_ELEMENT.search(blob):
            anchors += 1

    if anchors == 0:
        failures.append(
            "no concrete function, route handler, guard, schema check, or line-anchored evidence"
        )
    return failures


def specific_issue_failures(draft: AgentFindingDraft) -> list[str]:
    claim = draft.claim
    if _ISSUE_MARKERS.search(claim):
        return []

    for item in draft.evidence:
        snippet = item.snippet or ""
        for match in re.finditer(r"(?:function|def|class)\s+(\w+)", snippet):
            if match.group(1).lower() in claim.lower():
                return []
        for match in re.finditer(r"@app\.(?:get|post|put|patch|delete|route)\([\"']([^\"']+)", snippet):
            if match.group(1).lower() in claim.lower():
                return []

    return ["claim does not identify a specific missing or incorrect check"]


def affected_path_failures(
    draft: AgentFindingDraft,
    inventory: set[str],
    routes: set[str],
) -> list[str]:
    failures: list[str] = []
    for surface in draft.affected_surfaces:
        if is_route_surface(surface, routes):
            continue
        if is_valid_repo_file_path(surface, inventory):
            continue
        failures.append(f"affected surface is not a route or repo file path: {surface}")
    return failures


def reproduction_failures(draft: AgentFindingDraft, file_paths: list[str]) -> list[str]:
    if not file_paths:
        return ["no repo file paths to tie safe reproduction"]
    repro = " ".join(draft.safe_reproduction.steps).lower()
    if not any(path.lower() in repro for path in file_paths):
        return ["safe reproduction steps do not reference affected file paths"]
    return []


def split_surfaces_and_files(
    draft: AgentFindingDraft,
    inventory: set[str],
    routes: set[str],
) -> tuple[list[str], list[str]]:
    surfaces: set[str] = set()
    files: set[str] = set()

    for surface in draft.affected_surfaces:
        if is_route_surface(surface, routes):
            surfaces.add(surface.strip())
        elif is_valid_repo_file_path(surface, inventory):
            files.add(surface.strip())

    for item in draft.evidence:
        if item.route:
            surfaces.add(item.route.strip())
        if item.path and item.type != "skill" and is_valid_repo_file_path(item.path, inventory):
            files.add(item.path.strip())

    return sorted(surfaces), sorted(files)
