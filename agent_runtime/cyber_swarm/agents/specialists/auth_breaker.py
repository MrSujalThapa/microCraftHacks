"""Auth breaker specialist agent (legacy alias for auth-boundary)."""

from __future__ import annotations

from cyber_swarm.agents.specialists.auth_boundary import run_auth_boundary
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_auth_breaker(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> AgentFindingDraft | None:
    return run_auth_boundary(
        hypothesis,
        runtime_input,
        selected_context,
        evidence_packs,
        attack_graph=attack_graph,
    )
