"""Auth boundary specialist — graph-backed cross-file auth gaps."""

from __future__ import annotations

from cyber_swarm.evidence.draft_helpers import build_auth_draft
from cyber_swarm.evidence.graph_drafts import (
    build_graph_auth_boundary_draft,
    build_graph_frontend_backend_draft,
)
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_auth_boundary(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
) -> AgentFindingDraft | None:
    packs = evidence_packs or []
    if attack_graph is not None:
        draft = build_graph_frontend_backend_draft(
            hypothesis, runtime_input, attack_graph, packs, selected_context
        )
        if draft is not None:
            return draft
        draft = build_graph_auth_boundary_draft(
            hypothesis, runtime_input, attack_graph, packs, selected_context
        )
        if draft is not None:
            return draft
    if not packs:
        return None
    legacy = build_auth_draft(hypothesis, runtime_input, packs, selected_context)
    if legacy is not None and legacy.graph_path is None:
        return None
    return legacy
