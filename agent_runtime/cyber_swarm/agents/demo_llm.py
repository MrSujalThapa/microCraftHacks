"""Focused demo-mode LLM finding generation."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from cyber_swarm.agents.demo_prompt import (
    DEMO_PROMPT_VERSION,
    build_demo_llm_payload,
    latency_caps,
    select_top_evidence_packs,
    select_top_graph_paths,
)
from cyber_swarm.agents.shared import skills_for_agent, static_reproduction
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import packs_by_id
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.metrics.timing import estimate_tokens
from cyber_swarm.models.agents import AgentFindingDraft, QaComparison
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.providers.base import AgentProvider
from cyber_swarm.providers.prompts import BASELINE_SYSTEM_PROMPT
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.schemas.llm_cache import (
    evidence_hash,
    graph_hash,
    llm_cache_key,
    llm_cache_path,
    read_llm_cache,
    write_llm_cache,
)

DEMO_FINDINGS_SYSTEM_PROMPT = (
    BASELINE_SYSTEM_PROMPT
    + "\n\n"
    + "Demo task: Given evidence packs, attack graph paths, and deterministic candidates, "
    "produce at most the requested number of concrete security findings OR reject all. "
    "Prioritize secret/config exposure, auth boundaries, BOLA, service-role misuse, and AI/tool side effects. "
    "Do not emit generic route validation or public health endpoint noise. "
    "Every finding must cite evidence_pack_ids from the supplied evidencePacks list."
)

_SPECIALIST_BY_AGENT = {
    "auth": "auth-boundary",
    "api": "api-abuse",
    "secrets": "secrets-config",
    "storage": "storage-access",
    "ai": "ai-action-boundary",
}


def _canonical_specialist(agent_type: str, specialist: str | None = None) -> str:
    if specialist in _SPECIALIST_BY_AGENT.values():
        return specialist
    return _SPECIALIST_BY_AGENT.get(agent_type, "api-abuse")


def build_demo_llm_user_prompt(
    *,
    evidence_packs: list[EvidencePack],
    attack_graph: AttackGraph | None,
    routed_skills: dict[str, Any],
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
) -> tuple[str, dict[str, Any], list[EvidencePack], list[str]]:
    payload = build_demo_llm_payload(
        evidence_packs=evidence_packs,
        attack_graph=attack_graph,
        routed_skills=routed_skills,
        deterministic_candidates=deterministic_candidates,
        runtime_config=runtime_config,
    )
    caps = latency_caps(runtime_config)
    selected_packs = select_top_evidence_packs(evidence_packs, max_packs=caps["max_packs"])
    graph_paths = select_top_graph_paths(attack_graph, max_paths=caps["max_paths"])
    path_ids = [str(item.get("pathId", "")) for item in graph_paths if item.get("pathId")]
    user = json.dumps(payload, separators=(",", ":"))
    return user, payload, selected_packs, path_ids


def run_demo_findings_with_provider(
    provider: AgentProvider,
    runtime_input: RuntimeInput,
    *,
    evidence_packs: list[EvidencePack],
    attack_graph: AttackGraph | None,
    routed_skills: dict[str, Any],
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
    scan_hash: str | None = None,
    output_path: str | None = None,
) -> tuple[list[AgentFindingDraft], dict[str, Any]]:
    prompt_started = time.perf_counter()
    user, prompt_payload, selected_packs, path_ids = build_demo_llm_user_prompt(
        evidence_packs=evidence_packs,
        attack_graph=attack_graph,
        routed_skills=routed_skills,
        deterministic_candidates=deterministic_candidates,
        runtime_config=runtime_config,
    )
    prompt_build_ms = round((time.perf_counter() - prompt_started) * 1000, 2)
    input_token_estimate = estimate_tokens(DEMO_FINDINGS_SYSTEM_PROMPT + user)

    cache_meta: dict[str, Any] = {
        "hit": False,
        "promptVersion": DEMO_PROMPT_VERSION,
        "latencyMode": runtime_config.effective_latency,
        "inputTokenEstimate": input_token_estimate,
        "promptBuildMs": prompt_build_ms,
    }

    evidence_key = evidence_hash(selected_packs)
    graph_key = graph_hash(attack_graph, path_ids)
    cache_key = llm_cache_key(
        scan_hash=scan_hash or "",
        evidence_key=evidence_key,
        graph_key=graph_key,
        provider=runtime_config.provider,
        model=runtime_config.model,
        latency_mode=runtime_config.effective_latency,
    )
    cache_meta["cacheKey"] = cache_key
    cache_meta["evidenceHash"] = evidence_key
    cache_meta["graphHash"] = graph_key

    llm_payload: dict[str, Any] | None = None
    call_meta: dict[str, Any] | None = None

    if (
        output_path
        and scan_hash
        and not runtime_config.force_llm
    ):
        cached = read_llm_cache(llm_cache_path(Path(output_path), cache_key))
        if cached is not None:
            llm_payload = cached.get("llmPayload")
            call_meta = cached.get("call")
            cache_meta["hit"] = True

    if llm_payload is None:
        call_started = time.perf_counter()
        result = provider.complete_json(
            system=DEMO_FINDINGS_SYSTEM_PROMPT,
            user=user,
            purpose="demo_findings",
        )
        model_latency_ms = round((time.perf_counter() - call_started) * 1000, 2)
        llm_payload = result.payload
        call_meta = asdict(result)
        cache_meta["hit"] = False
        cache_meta["outputTokens"] = result.completion_tokens
        cache_meta["modelLatencyMs"] = model_latency_ms

        if output_path and scan_hash:
            write_llm_cache(
                llm_cache_path(Path(output_path), cache_key),
                cache_key=cache_key,
                scan_hash=scan_hash,
                evidence_key=evidence_key,
                graph_key=graph_key,
                provider=runtime_config.provider,
                model=runtime_config.model,
                latency_mode=runtime_config.effective_latency,
                llm_payload=llm_payload,
                call_meta=call_meta or {},
            )
    else:
        cache_meta["outputTokens"] = (call_meta or {}).get("completion_tokens")
        cache_meta["modelLatencyMs"] = (call_meta or {}).get("elapsed_ms", 0)

    max_findings = latency_caps(runtime_config)["max_findings"]
    drafts = parse_demo_findings_payload(
        llm_payload or {},
        runtime_input,
        evidence_packs,
        max_findings=max_findings,
    )

    stage_metrics = {
        "mode": "openai" if runtime_config.provider == "openai" else runtime_config.provider,
        "purpose": "demo_findings",
        "call": call_meta,
        "llmCache": cache_meta,
        "draftCount": len(drafts),
        "promptVersion": DEMO_PROMPT_VERSION,
    }
    return drafts, stage_metrics


def parse_demo_findings_payload(
    payload: dict[str, Any],
    runtime_input: RuntimeInput,
    evidence_packs: list[EvidencePack],
    *,
    max_findings: int,
) -> list[AgentFindingDraft]:
    if payload.get("reject_all") is True:
        return []

    pack_index = packs_by_id(evidence_packs)
    parsed: list[AgentFindingDraft] = []

    for index, item in enumerate(payload.get("findings", [])):
        if not isinstance(item, dict):
            continue
        draft = _finding_item_to_draft(
            item,
            runtime_input,
            pack_index,
            draft_index=index + 1,
        )
        if draft is not None:
            parsed.append(draft)
        if len(parsed) >= max_findings:
            break

    return parsed


def _finding_item_to_draft(
    item: dict[str, Any],
    runtime_input: RuntimeInput,
    pack_index: dict[str, EvidencePack],
    *,
    draft_index: int,
) -> AgentFindingDraft | None:
    pack_ids = [
        str(value)
        for value in item.get("evidence_pack_ids", [])
        if isinstance(value, str) and value.strip()
    ]
    if not pack_ids:
        return None

    evidence = []
    for pack_id in pack_ids:
        pack = pack_index.get(pack_id)
        if pack is None:
            return None
        explanation = redact_secrets(
            str(item.get("claim", item.get("title", "Security finding")))[:240]
        )
        evidence.append(evidence_from_pack(pack, explanation))

    agent_type = str(item.get("agent_type", "secrets"))
    specialist = _canonical_specialist(
        agent_type,
        str(item.get("specialist", "")) if item.get("specialist") else None,
    )
    title = redact_secrets(str(item.get("title", "Security finding")))
    claim = redact_secrets(str(item.get("claim", title)))
    surfaces = [
        str(surface)
        for surface in item.get("affected_surfaces", [])
        if isinstance(surface, str)
    ]

    qa = QaComparison(
        why_qa_may_miss=str(item.get("why_qa_misses_this", "")),
        why_review_may_miss=str(item.get("why_code_review_misses_this", "")),
        suggested_regression_test=str(item.get("suggested_regression_test", "")),
    )

    return AgentFindingDraft(
        id=str(item.get("id", f"draft-llm-{draft_index}")),
        title=title,
        vulnerability_class=str(item.get("vulnerability_class", "security-misconfiguration")),
        claim=claim,
        affected_surfaces=surfaces,
        evidence=evidence,
        impact_hypothesis=redact_secrets(str(item.get("impact_hypothesis", ""))),
        attack_path=redact_secrets(str(item.get("attack_path", ""))),
        safe_reproduction=static_reproduction(
            [
                f"Open {evidence[0].path}:{evidence[0].line_start} and inspect cited evidence.",
                qa.suggested_regression_test or "Add regression coverage for this boundary.",
            ],
            claim[:180] or "Static evidence supports the reported issue.",
        ),
        confidence=item.get("confidence", "medium"),  # type: ignore[arg-type]
        agent_type=agent_type,
        specialist=specialist,
        selected_skills=skills_for_agent(runtime_input, agent_type),
        retrieval_trace=[],
        qa_comparison=qa if any((qa.why_qa_may_miss, qa.why_review_may_miss, qa.suggested_regression_test)) else None,
    )
