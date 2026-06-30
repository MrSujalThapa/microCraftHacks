"""API abuse specialist agent."""

from __future__ import annotations

from cyber_swarm.evidence.draft_helpers import build_api_abuse_draft
from cyber_swarm.evidence.graph_drafts import build_graph_api_abuse_draft
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_api_abuse(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> AgentFindingDraft | None:
    packs = evidence_packs or []
    if attack_graph is not None and packs:
        draft = build_graph_api_abuse_draft(
            hypothesis, runtime_input, attack_graph, packs, selected_context
        )
        if draft is not None:
            return draft
        return None
    if not packs:
        return None
    return build_api_abuse_draft(hypothesis, runtime_input, packs, selected_context)
