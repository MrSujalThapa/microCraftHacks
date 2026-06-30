"""AI action boundary specialist."""

from __future__ import annotations

from cyber_swarm.evidence.graph_drafts import build_graph_ai_action_draft
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_ai_action_boundary(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> AgentFindingDraft | None:
    if attack_graph is None or not evidence_packs:
        return None
    return build_graph_ai_action_draft(
        hypothesis, runtime_input, attack_graph, evidence_packs, selected_context
    )
