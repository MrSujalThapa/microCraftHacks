"""Run static specialist agents and validate draft findings."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.agents.specialists.ai_action_boundary import run_ai_action_boundary
from cyber_swarm.agents.specialists.api_abuse import run_api_abuse
from cyber_swarm.agents.specialists.auth_boundary import run_auth_boundary
from cyber_swarm.agents.specialists.auth_breaker import run_auth_breaker
from cyber_swarm.agents.specialists.base import is_vague_draft
from cyber_swarm.agents.specialists.object_ownership import run_object_ownership
from cyber_swarm.agents.specialists.secrets_config import run_secrets_config
from cyber_swarm.agents.specialists.storage_access import run_storage_access
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.seek import max_seek_iterations, seek_evidence_pack, seek_requests_for_nodes
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis, RejectedFindingDraft
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput

SpecialistRunner = (
    type[object]  # placeholder for callable signature
)

SPECIALISTS = {
    "auth-boundary": run_auth_boundary,
    "auth-breaker": run_auth_breaker,
    "object-ownership": run_object_ownership,
    "api-abuse": run_api_abuse,
    "storage-access": run_storage_access,
    "ai-action-boundary": run_ai_action_boundary,
    "secrets-config": run_secrets_config,
}


def _next_pack_id(packs: list[EvidencePack]) -> str:
    numbers = []
    for pack in packs:
        if pack.id.startswith("ep-"):
            try:
                numbers.append(int(pack.id.split("-", 1)[1]))
            except ValueError:
                continue
    return f"ep-{max(numbers, default=0) + 1:03d}"


def _invoke_specialist(
    runner,
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    packs: list[EvidencePack],
    attack_graph: AttackGraph | None,
) -> AgentFindingDraft | None:
    return runner(
        hypothesis,
        runtime_input,
        selected_context,
        packs,
        attack_graph=attack_graph,
    )


def _run_with_evidence_seek(
    runner,
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack],
    attack_graph: AttackGraph | None,
    *,
    demo: bool,
) -> AgentFindingDraft | None:
    packs = list(evidence_packs)
    draft = _invoke_specialist(runner, hypothesis, runtime_input, selected_context, packs, attack_graph)
    if draft is not None or attack_graph is None:
        return draft

    slice_graph = attack_graph.slice_for_specialist(hypothesis.specialist)
    requests = seek_requests_for_nodes(slice_graph.nodes[:6])
    project_root = Path(runtime_input.repo.project_root)

    for _ in range(max_seek_iterations(demo=demo)):
        if not requests:
            break
        request = requests.pop(0)
        supplemental = seek_evidence_pack(
            project_root,
            request,
            next_pack_id=_next_pack_id(packs),
        )
        if supplemental is None:
            continue
        packs.append(supplemental)
        draft = _invoke_specialist(runner, hypothesis, runtime_input, selected_context, packs, attack_graph)
        if draft is not None:
            return draft

    return None


def run_specialists(
    runtime_input: RuntimeInput,
    hypotheses: list[AttackHypothesis],
    selected_context: list[RetrievedContext],
    evidence_packs: list[EvidencePack] | None = None,
    attack_graph: AttackGraph | None = None,
    *,
    demo: bool = False,
) -> tuple[list[AgentFindingDraft], list[RejectedFindingDraft]]:
    drafts: list[AgentFindingDraft] = []
    rejected: list[RejectedFindingDraft] = []
    packs = evidence_packs or []

    for hypothesis in hypotheses:
        runner = SPECIALISTS.get(hypothesis.specialist)
        if runner is None:
            continue

        draft = _run_with_evidence_seek(
            runner,
            hypothesis,
            runtime_input,
            selected_context,
            packs,
            attack_graph,
            demo=demo,
        )
        if draft is None:
            rejected.append(
                RejectedFindingDraft(
                    draft_id=f"reject-{hypothesis.id}",
                    reason="Insufficient graph-backed evidence for specialist analysis",
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
