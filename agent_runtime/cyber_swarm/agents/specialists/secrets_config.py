"""Secrets and config specialist agent."""

from __future__ import annotations

from cyber_swarm.evidence.draft_helpers import build_secrets_draft
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_secrets_config(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
) -> AgentFindingDraft | None:
    if not evidence_packs:
        return None
    return build_secrets_draft(hypothesis, runtime_input, evidence_packs, selected_context)
