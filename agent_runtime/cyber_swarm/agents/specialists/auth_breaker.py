"""Auth breaker specialist agent."""

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


def run_auth_breaker(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    relevant = context_for_paths(selected_context, hypothesis.target_files)
    auth_context = [
        item
        for item in production_context(selected_context)
        if item.context_category in {"auth", "route", "source"}
        and any(token in (item.source_path or "").lower() for token in ("auth", "middleware", "login"))
    ]
    evidence_items = relevant or auth_context[:2]
    if not evidence_items:
        return None

    routes = hypothesis.target_surfaces or [
        item.source_path for item in evidence_items if item.context_category == "route"
    ]
    files = hypothesis.target_files or [item.source_path for item in evidence_items if item.source_path]
    evidence = [
        evidence_from_context(item, "Auth-related production context supports access-control review")
        for item in evidence_items[:3]
    ]

    return AgentFindingDraft(
        id="draft-auth-1",
        title="Potential auth boundary enforcement gap",
        vulnerability_class=hypothesis.vulnerability_class,
        claim=(
            "Static evidence shows auth middleware or login route handlers that should enforce "
            "access control before sensitive API routes are reached."
        ),
        affected_surfaces=[route for route in routes if route][:6],
        evidence=evidence,
        impact_hypothesis="Missing or inconsistent auth checks could allow unauthorized API access.",
        attack_path="Review login/auth handler flow and compare protected route coverage.",
        safe_reproduction=static_reproduction(
            [
                "Inspect auth middleware and login route handler in identified files.",
                "Map protected routes against middleware coverage without sending live requests.",
            ],
            "Identify routes lacking explicit auth enforcement in static code paths.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=skills_for_agent(runtime_input, "auth"),
        retrieval_trace=[item.id for item in evidence_items],
    )
