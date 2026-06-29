"""Build specialist drafts from line-level evidence packs."""

from __future__ import annotations

from cyber_swarm.agents.shared import (
    file_contains_secret_pattern,
    skills_for_agent,
    static_reproduction,
)
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.secret_packs import is_secret_evidence_pack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput



def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _packs_for_hypothesis(
    packs: list[EvidencePack],
    hypothesis: AttackHypothesis,
    *,
    surface_types: set[str] | None = None,
) -> list[EvidencePack]:
    targets = {_normalize(path) for path in hypothesis.target_files}
    selected: list[EvidencePack] = []
    for pack in packs:
        if surface_types and pack.surface_type not in surface_types:
            continue
        if targets and _normalize(pack.path) not in targets:
            continue
        selected.append(pack)
    if selected:
        return selected
    if surface_types:
        return [pack for pack in packs if pack.surface_type in surface_types]
    return list(packs)


def build_auth_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    packs = _packs_for_hypothesis(evidence_packs, hypothesis, surface_types={"auth", "api", "source"})
    if not packs:
        return None

    for pack in packs:
        snippet_lower = pack.snippet.lower().replace(" ", "")
        if "httpbearer" in snippet_lower and "auto_error=false" in snippet_lower:
            symbol = pack.symbol or "_bearer_scheme"
            explanation = (
                f"{symbol} in {pack.path}:{pack.line_start} sets HTTPBearer(auto_error=False), "
                "so missing Authorization headers are not rejected before route handlers execute."
            )
            routes = [item for item in hypothesis.target_surfaces if item.startswith("/")]
            if pack.route:
                routes = [pack.route, *routes]
            return AgentFindingDraft(
                id=f"draft-{hypothesis.id}",
                title=f"HTTPBearer(auto_error=False) in {pack.path} skips automatic credential rejection",
                vulnerability_class=hypothesis.vulnerability_class,
                claim=(
                    f"{symbol} in {pack.path} uses HTTPBearer(auto_error=False), which means missing "
                    "Authorization headers are not rejected before protected route handlers execute."
                ),
                affected_surfaces=routes[:4],
                evidence=[evidence_from_pack(pack, explanation)],
                impact_hypothesis="Unauthenticated requests can reach handlers that assume credentials were validated upstream.",
                attack_path=(
                    f"Trace Depends({symbol}) usage in {pack.path} and confirm handlers treat absent "
                    "Authorization headers as unauthenticated."
                ),
                safe_reproduction=static_reproduction(
                    [
                        f"Open {pack.path}:{pack.line_start} and inspect {symbol} for auto_error=False.",
                        "Trace route dependencies that rely on this bearer scheme without explicit 401 handling.",
                    ],
                    "Bearer scheme accepts requests without raising HTTP 401 for missing Authorization headers.",
                ),
                confidence="high",
                agent_type="auth",
                specialist="auth-breaker",
                selected_skills=skills_for_agent(runtime_input, "auth"),
                retrieval_trace=[item.id for item in selected_context[:3]],
            )

    route_packs = [pack for pack in packs if pack.kind == "route_decorator"]
    if route_packs:
        pack = route_packs[0]
        route = pack.route or hypothesis.target_surfaces[0] if hypothesis.target_surfaces else "/api/route"
        explanation = (
            f"{pack.symbol} in {pack.path}:{pack.line_start} defines route {route} without a visible "
            "auth dependency in the handler signature."
        )
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"Route {route} handler lacks visible auth dependency",
            vulnerability_class=hypothesis.vulnerability_class,
            claim=(
                f"The {pack.symbol} handler in {pack.path} exposes {route} without a visible "
                "get_current_user, Depends(auth), or equivalent guard in the static handler definition."
            ),
            affected_surfaces=[route],
            evidence=[evidence_from_pack(pack, explanation)],
            impact_hypothesis="Missing auth dependency on the handler can allow unauthenticated access to the route.",
            attack_path=f"Review {pack.path}:{pack.line_start} for auth dependencies on {route}.",
            safe_reproduction=static_reproduction(
                [
                    f"Open {pack.path}:{pack.line_start} and inspect the {pack.symbol} handler signature.",
                    f"Confirm {route} does not declare an auth dependency before business logic.",
                ],
                f"Handler for {route} lacks visible auth enforcement in static code.",
            ),
            confidence="medium",
            agent_type="auth",
            specialist="auth-breaker",
            selected_skills=skills_for_agent(runtime_input, "auth"),
            retrieval_trace=[item.id for item in selected_context[:3]],
        )

    dependency_packs = [pack for pack in packs if pack.kind == "dependency"]
    if dependency_packs:
        pack = dependency_packs[0]
        explanation = (
            f"{pack.symbol} in {pack.path}:{pack.line_start} is injected without visible "
            "authorization checks in the surrounding handler code."
        )
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"{pack.symbol} dependency lacks visible authorization enforcement",
            vulnerability_class=hypothesis.vulnerability_class,
            claim=(
                f"{pack.symbol} in {pack.path} is used as a FastAPI dependency without visible "
                "role or scope validation before sensitive handler logic executes."
            ),
            affected_surfaces=[route for route in hypothesis.target_surfaces if route.startswith("/")][:4],
            evidence=[evidence_from_pack(pack, explanation)],
            impact_hypothesis="Authenticated but under-privileged users may reach sensitive handler logic.",
            attack_path=f"Review {pack.path}:{pack.line_start} for authorization checks after {pack.symbol} injection.",
            safe_reproduction=static_reproduction(
                [
                    f"Open {pack.path}:{pack.line_start} and inspect {pack.symbol} usage.",
                    "Confirm no role or scope validation wraps the dependency result.",
                ],
                f"{pack.symbol} is consumed without visible authorization guardrails.",
            ),
            confidence="medium",
            agent_type="auth",
            specialist="auth-breaker",
            selected_skills=skills_for_agent(runtime_input, "auth"),
            retrieval_trace=[item.id for item in selected_context[:3]],
        )

    return None


def build_api_abuse_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    packs = _packs_for_hypothesis(evidence_packs, hypothesis, surface_types={"api", "source"})
    route_packs = [pack for pack in packs if pack.kind in {"route_decorator", "route_handler", "function"}]
    if not route_packs:
        return None

    pack = route_packs[0]
    route = pack.route or (hypothesis.target_surfaces[0] if hypothesis.target_surfaces else None)
    route_label = route or pack.symbol or "API handler"
    explanation = (
        f"{pack.symbol} in {pack.path}:{pack.line_start} handles {route_label} requests "
        "and lacks schema validation or authorization checks in the static handler definition."
    )
    surfaces = [route] if route else []
    return AgentFindingDraft(
        id=f"draft-{hypothesis.id}",
        title=f"{route_label} handler lacks visible validation in {pack.path}",
        vulnerability_class=hypothesis.vulnerability_class,
        claim=(
            f"The {pack.symbol} handler in {pack.path} processes {route_label} requests and "
            "lacks input validation or authorization checks in the static handler definition."
        ),
        affected_surfaces=surfaces,
        evidence=[evidence_from_pack(pack, explanation)],
        impact_hypothesis="Missing validation on the handler can enable abusive or malformed request processing.",
        attack_path=f"Review {pack.path}:{pack.line_start} for validation and auth checks on {route_label}.",
        safe_reproduction=static_reproduction(
            [
                f"Open {pack.path}:{pack.line_start} and inspect the {pack.symbol} handler body.",
                f"Confirm {route_label} lacks visible schema validation before processing.",
            ],
            f"Handler for {route_label} lacks visible validation in static code.",
        ),
        confidence="medium",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=skills_for_agent(runtime_input, "api"),
        retrieval_trace=[item.id for item in selected_context[:3]],
    )


def _secret_draft_from_pack(
    pack: EvidencePack,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    *,
    draft_id: str,
    vulnerability_class: str = "secret-exposure",
) -> AgentFindingDraft:
    key_name = pack.symbol or "credential key"
    explanation = (
        f"{key_name} appears in {pack.path}:{pack.line_start} with a credential-like assignment "
        "that should not contain live secrets in the repository."
    )
    return AgentFindingDraft(
        id=draft_id,
        title=f"Hardcoded {key_name} in {pack.path}",
        vulnerability_class=vulnerability_class,
        claim=(
            f"{key_name} in {pack.path}:{pack.line_start} is assigned in tracked configuration "
            "without using a secret manager or runtime-only environment injection."
        ),
        affected_surfaces=[],
        evidence=[evidence_from_pack(pack, explanation)],
        impact_hypothesis="Exposed secrets in tracked files can enable credential theft or lateral movement.",
        attack_path=f"Inspect {pack.path}:{pack.line_start} for {key_name} and rotate any exposed value.",
        safe_reproduction=static_reproduction(
            [
                f"Open {pack.path}:{pack.line_start} and confirm {key_name} is redacted in reports.",
                "Verify production reads the value from environment or a secret manager.",
            ],
            f"{key_name} assignment is visible in static configuration at {pack.path}:{pack.line_start}.",
        ),
        confidence="high",
        agent_type="secrets",
        specialist="secrets-config",
        selected_skills=skills_for_agent(runtime_input, "secrets"),
        retrieval_trace=[item.id for item in selected_context[:3]],
    )


def build_deterministic_secret_drafts(
    runtime_input: RuntimeInput,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> list[AgentFindingDraft]:
    """Build secret exposure drafts from env-key evidence packs without LLM involvement."""
    drafts: list[AgentFindingDraft] = []
    seen: set[tuple[str, str, int]] = set()

    for index, pack in enumerate(evidence_packs, start=1):
        if not is_secret_evidence_pack(pack):
            continue
        dedupe_key = (pack.path, pack.symbol or "", pack.line_start)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        drafts.append(
            _secret_draft_from_pack(
                pack,
                runtime_input,
                selected_context,
                draft_id=f"draft-det-secret-{index}",
            )
        )

    return drafts


def build_secrets_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    packs = _packs_for_hypothesis(evidence_packs, hypothesis, surface_types={"config", "auth", "dependency"})
    secret_packs = [pack for pack in packs if is_secret_evidence_pack(pack)]
    if not secret_packs:
        return None

    return _secret_draft_from_pack(
        secret_packs[0],
        runtime_input,
        selected_context,
        draft_id=f"draft-{hypothesis.id}",
        vulnerability_class=hypothesis.vulnerability_class,
    )
