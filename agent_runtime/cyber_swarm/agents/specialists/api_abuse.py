"""API abuse specialist agent."""

from __future__ import annotations

from cyber_swarm.agents.specialists.base import (
    context_for_paths,
    evidence_from_context,
    production_context,
    skills_for_agent,
    static_reproduction,
)
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_api_abuse(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    relevant = context_for_paths(selected_context, hypothesis.target_files)
    route_context = [
        item
        for item in production_context(selected_context)
        if item.context_category in {"route", "source"}
        and any(token in (item.excerpt + (item.source_path or "")).lower() for token in ("api", "route", "handler"))
    ]
    evidence_items = relevant or route_context[:2]
    if not evidence_items:
        return None

    routes = hypothesis.target_surfaces or []
    evidence = [
        evidence_from_context(item, "API route or handler context supports schema/abuse review")
        for item in evidence_items[:3]
    ]

    return AgentFindingDraft(
        id="draft-api-1",
        title="Potential API abuse via weak handler validation",
        vulnerability_class=hypothesis.vulnerability_class,
        claim=(
            "Static route/handler evidence indicates API endpoints that should enforce input validation "
            "and authorization before processing sensitive requests."
        ),
        affected_surfaces=routes[:8],
        evidence=evidence,
        impact_hypothesis="Missing validation or authorization on API handlers can enable abuse or data exposure.",
        attack_path="Trace API route handlers and inspect validation/auth checks statically.",
        safe_reproduction=static_reproduction(
            [
                "Review mapped API route handlers in identified source files.",
                "Check for schema validation, auth guards, and error handling without live requests.",
            ],
            "Document handlers lacking visible validation or auth checks.",
        ),
        confidence="medium",
        agent_type="api",
        specialist="api-abuse",
        selected_skills=skills_for_agent(runtime_input, "api"),
        retrieval_trace=[item.id for item in evidence_items],
    )
