"""Focused demo-mode LLM candidate confirmation."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from cyber_swarm.agents.demo_prompt import (
    DEMO_PROMPT_VERSION,
    build_demo_llm_payload,
    effective_max_confirmations,
    latency_caps,
    select_top_evidence_packs,
    select_top_graph_paths,
)
from cyber_swarm.metrics.timing import estimate_tokens
from cyber_swarm.models.agents import AgentFindingDraft, QaComparison, SafeReproduction
from cyber_swarm.models.attack_graph import AttackGraph
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.providers.base import AgentProvider
from cyber_swarm.providers.prompts import BASELINE_SYSTEM_PROMPT, REPAIR_SYSTEM_PROMPT
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.schemas.llm_cache import (
    llm_cache_key,
    llm_cache_path,
    read_llm_cache,
    stable_evidence_hash,
    stable_graph_hash,
    write_llm_cache,
)

DEMO_FINDINGS_SYSTEM_PROMPT = (
    BASELINE_SYSTEM_PROMPT
    + "\n\n"
    + "Demo task: confirm or reject deterministicCandidates using supplied evidence only. "
    + "Return short JSON with confirmations[] or reject_all=true. "
    + "Never invent file paths, lines, snippets, or evidence pack IDs. "
    + "One sentence per string field (recommended_fix and suggested_regression_test included). "
    + "No markdown. No prose outside JSON."
)

DEMO_LLM_FALLBACK_MESSAGE = (
    "LLM returned no usable confirmation; preserved verifier-backed deterministic evidence."
)


def build_demo_llm_user_prompt(
    *,
    evidence_packs: list,
    attack_graph: AttackGraph | None,
    routed_skills: dict[str, Any],
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
) -> tuple[str, dict[str, Any], list, list[str]]:
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
    evidence_packs: list,
    attack_graph: AttackGraph | None,
    routed_skills: dict[str, Any],
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
    content_fingerprint: str | None = None,
    scan_report: dict[str, Any] | None = None,
    output_path: str | None = None,
) -> tuple[list[AgentFindingDraft], dict[str, Any]]:
    prompt_started = time.perf_counter()
    user, _prompt_payload, selected_packs, path_ids = build_demo_llm_user_prompt(
        evidence_packs=evidence_packs,
        attack_graph=attack_graph,
        routed_skills=routed_skills,
        deterministic_candidates=deterministic_candidates,
        runtime_config=runtime_config,
    )
    prompt_build_ms = round((time.perf_counter() - prompt_started) * 1000, 2)
    caps = latency_caps(runtime_config)
    max_output_tokens = caps["max_output_tokens"]
    input_token_estimate = estimate_tokens(DEMO_FINDINGS_SYSTEM_PROMPT + user)

    evidence_key = stable_evidence_hash(selected_packs)
    graph_key = stable_graph_hash(attack_graph, path_ids)
    fingerprint = content_fingerprint or ""
    cache_key = llm_cache_key(
        content_fingerprint=fingerprint,
        evidence_key=evidence_key,
        graph_key=graph_key,
        provider=runtime_config.provider,
        model=runtime_config.model,
        latency_mode=runtime_config.effective_latency,
    )

    cache_meta: dict[str, Any] = {
        "hit": False,
        "promptVersion": DEMO_PROMPT_VERSION,
        "latencyMode": runtime_config.effective_latency,
        "inputTokenEstimate": input_token_estimate,
        "promptBuildMs": prompt_build_ms,
        "cacheKey": cache_key,
        "cacheKeyPrefix": cache_key[:8],
        "evidenceHash": evidence_key,
        "graphHash": graph_key,
        "contentFingerprint": fingerprint,
        "maxOutputTokens": max_output_tokens,
    }

    llm_payload: dict[str, Any] | None = None
    call_meta: dict[str, Any] | None = None
    repair_attempted = False

    if output_path and fingerprint and not runtime_config.force_llm:
        cached = read_llm_cache(llm_cache_path(Path(output_path), cache_key))
        if cached is not None:
            llm_payload = cached.get("llmPayload")
            call_meta = cached.get("call")
            cache_meta["hit"] = True

    provider_calls_attempted = 0

    if llm_payload is None:
        llm_payload, call_meta, repair_attempted, provider_calls_attempted = (
            _call_with_optional_repair(
                provider,
                user=user,
                deterministic_candidates=deterministic_candidates,
                runtime_config=runtime_config,
                max_output_tokens=max_output_tokens,
                scan_report=scan_report or {},
                evidence_packs=evidence_packs,
            )
        )
        cache_meta["hit"] = False
        cache_meta["outputTokens"] = (call_meta or {}).get("completion_tokens")
        cache_meta["modelLatencyMs"] = (call_meta or {}).get("elapsed_ms", 0)
        cache_meta["repairAttempted"] = repair_attempted

        if output_path and fingerprint:
            write_llm_cache(
                llm_cache_path(Path(output_path), cache_key),
                cache_key=cache_key,
                content_fingerprint=fingerprint,
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

    output_tokens = cache_meta.get("outputTokens")
    if isinstance(output_tokens, int) and output_tokens > max_output_tokens:
        cache_meta["outputTokenWarning"] = (
            f"output tokens {output_tokens} exceeded cap {max_output_tokens}"
        )

    drafts, merge_issues = merge_confirmations(
        deterministic_candidates,
        llm_payload or {},
        runtime_config=runtime_config,
    )

    confirmations_accepted = len(drafts)
    fallback_used = bool(deterministic_candidates) and confirmations_accepted == 0

    stage_metrics: dict[str, Any] = {
        "mode": runtime_config.provider,
        "purpose": "demo_findings",
        "call": call_meta,
        "llmCache": cache_meta,
        "draftCount": len(drafts),
        "confirmationsAccepted": confirmations_accepted,
        "providerCallsAttempted": provider_calls_attempted,
        "fallbackUsed": fallback_used,
        "mergeIssues": merge_issues,
        "promptVersion": DEMO_PROMPT_VERSION,
        "repairAttempted": repair_attempted,
    }
    if fallback_used:
        stage_metrics["fallbackMessage"] = DEMO_LLM_FALLBACK_MESSAGE
        stage_metrics["fallbackReason"] = (
            "LLM produced candidates, but none were confirmed for verification"
        )
    return drafts, stage_metrics


def _call_with_optional_repair(
    provider: AgentProvider,
    *,
    user: str,
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
    max_output_tokens: int,
    scan_report: dict[str, Any],
    evidence_packs: list,
) -> tuple[dict[str, Any], dict[str, Any], bool, int]:
    call_started = time.perf_counter()
    provider_calls_attempted = 0
    result = provider.complete_json(
        system=DEMO_FINDINGS_SYSTEM_PROMPT,
        user=user,
        purpose="demo_findings",
        max_output_tokens=max_output_tokens,
    )
    provider_calls_attempted += 1
    payload = result.payload
    call_meta = asdict(result)
    call_meta["elapsed_ms"] = round((time.perf_counter() - call_started) * 1000, 2)

    drafts, merge_issues = merge_confirmations(
        deterministic_candidates,
        payload,
        runtime_config=runtime_config,
    )
    if drafts or payload.get("reject_all") is True or not deterministic_candidates:
        return payload, call_meta, False, provider_calls_attempted

    repair_user = json.dumps(
        {
            "task": "repair_confirmations",
            "issues": merge_issues or ["No valid confirmations returned."],
            "original": json.loads(user),
            "badResponse": payload,
            "responseSchema": {
                "confirmations": [{"candidateId": "string", "confirmed": "boolean"}],
                "reject_all": "boolean",
            },
        },
        separators=(",", ":"),
    )
    repair_started = time.perf_counter()
    repair_result = provider.complete_json(
        system=REPAIR_SYSTEM_PROMPT,
        user=repair_user,
        purpose="demo_findings_repair",
        max_output_tokens=max_output_tokens,
    )
    provider_calls_attempted += 1
    repair_meta = asdict(repair_result)
    repair_meta["elapsed_ms"] = round((time.perf_counter() - repair_started) * 1000, 2)
    call_meta["repair"] = repair_meta
    call_meta["completion_tokens"] = (result.completion_tokens or 0) + (
        repair_result.completion_tokens or 0
    )
    call_meta["elapsed_ms"] = round((time.perf_counter() - call_started) * 1000, 2)
    return repair_result.payload, call_meta, True, provider_calls_attempted


def merge_confirmations(
    candidates: list[AgentFindingDraft],
    payload: dict[str, Any],
    *,
    runtime_config: RuntimeConfig,
) -> tuple[list[AgentFindingDraft], list[str]]:
    issues: list[str] = []
    if payload.get("reject_all") is True:
        return [], ["LLM rejected all candidates"]

    candidate_by_id = {draft.id: draft for draft in candidates}
    merged: list[AgentFindingDraft] = []
    max_confirmations = effective_max_confirmations(runtime_config, candidates)

    for item in payload.get("confirmations", []):
        if not isinstance(item, dict):
            issues.append("confirmation entry is not an object")
            continue
        if item.get("confirmed") is not True:
            continue

        candidate_id = str(item.get("candidateId", "")).strip()
        base = candidate_by_id.get(candidate_id)
        if base is None:
            issues.append(f"unknown candidateId: {candidate_id or 'missing'}")
            continue

        llm_pack_ids = {
            str(value).strip()
            for value in item.get("evidence_pack_ids", [])
            if isinstance(value, str) and value.strip()
        }
        if llm_pack_ids:
            base_pack_ids = {
                ref.evidence_pack_id for ref in base.evidence if ref.evidence_pack_id
            }
            if llm_pack_ids != base_pack_ids:
                issues.append(f"candidate {candidate_id} attempted to change evidence pack IDs")
                continue

        qa = QaComparison(
            why_qa_may_miss=_one_sentence(item.get("why_qa_misses_this", "")),
            why_review_may_miss=_one_sentence(item.get("why_code_review_misses_this", "")),
            suggested_regression_test=_one_sentence(item.get("suggested_regression_test", "")),
        )
        recommended_fix = _one_sentence(item.get("recommended_fix", ""))
        reproduction = base.safe_reproduction
        if recommended_fix:
            reproduction = SafeReproduction(
                mode=reproduction.mode,
                steps=[*reproduction.steps[:2], recommended_fix][:3],
                expected_result=reproduction.expected_result,
                safety_notes=reproduction.safety_notes,
            )

        merged.append(
            replace(
                base,
                qa_comparison=qa
                if any((qa.why_qa_may_miss, qa.why_review_may_miss, qa.suggested_regression_test))
                else None,
                safe_reproduction=reproduction,
            )
        )
        if len(merged) >= max_confirmations:
            break

    return merged, issues


def parse_demo_findings_payload(
    payload: dict[str, Any],
    runtime_input: RuntimeInput,
    evidence_packs: list,
    *,
    max_findings: int,
    deterministic_candidates: list[AgentFindingDraft] | None = None,
) -> list[AgentFindingDraft]:
    """Backward-compatible parse entrypoint used in tests."""
    del runtime_input, evidence_packs
    runtime_config = RuntimeConfig(mode="demo", latency="balanced")
    drafts, _ = merge_confirmations(
        deterministic_candidates or [],
        payload,
        runtime_config=runtime_config,
    )
    return drafts[:max_findings]


def _one_sentence(value: Any) -> str:
    text = redact_secrets(str(value or "")).strip()
    if not text:
        return ""
    first = text.split(". ")[0].strip()
    if len(first) > 180:
        return first[:177] + "..."
    return first if first.endswith(".") else f"{first}."
