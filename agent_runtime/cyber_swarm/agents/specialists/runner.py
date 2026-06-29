"""Run static specialist agents and validate draft findings."""

from __future__ import annotations

from cyber_swarm.agents.specialists.api_abuse import run_api_abuse
from cyber_swarm.agents.specialists.auth_breaker import run_auth_breaker
from cyber_swarm.agents.specialists.base import is_vague_draft
from cyber_swarm.agents.specialists.secrets_config import run_secrets_config
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis, RejectedFindingDraft
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput

SPECIALISTS = {
    "auth-breaker": run_auth_breaker,
    "api-abuse": run_api_abuse,
    "secrets-config": run_secrets_config,
}


def run_specialists(
    runtime_input: RuntimeInput,
    hypotheses: list[AttackHypothesis],
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
) -> tuple[list[AgentFindingDraft], list[RejectedFindingDraft]]:
    drafts: list[AgentFindingDraft] = []
    rejected: list[RejectedFindingDraft] = []
    packs = evidence_packs or []

    for hypothesis in hypotheses:
        runner = SPECIALISTS.get(hypothesis.specialist)
        if runner is None:
            continue
        draft = runner(hypothesis, runtime_input, selected_context, packs)
        if draft is None:
            rejected.append(
                RejectedFindingDraft(
                    draft_id=f"reject-{hypothesis.id}",
                    reason="Insufficient line-level evidence packs for specialist analysis",
                    missing_evidence=hypothesis.required_evidence,
                )
            )
            continue

        vague, missing = is_vague_draft(draft)
        if vague:
            rejected.append(
                RejectedFindingDraft(
                    draft_id=draft.id,
                    reason="Draft finding rejected as vague or under-evidenced",
                    missing_evidence=missing,
                )
            )
            continue

        drafts.append(draft)

    return drafts, rejected
