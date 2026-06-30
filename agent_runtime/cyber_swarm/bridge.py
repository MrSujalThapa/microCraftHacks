"""Deterministic JSON bridge from TypeScript scan artifacts to findings output."""

from __future__ import annotations

import time
from pathlib import Path

from cyber_swarm.graph.workflow import run_workflow
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.schemas.cache import (
    CACHE_MISS_MESSAGE,
    CacheReplayError,
    copy_cached_findings,
    find_cached_findings,
    scan_content_hash,
    write_cache_metadata,
)
from cyber_swarm.demo.diagnostics import print_rejection_diagnostics
from cyber_swarm.schemas.io import write_json
from cyber_swarm.schemas.report_md import write_markdown_report


def _print_summary(output: dict) -> None:
    metrics = output.get("metrics", {})
    activation = metrics.get("activation", {})
    verifier = metrics.get("verifier", {})
    ranking = metrics.get("risk_ranking", {})
    runtime = metrics.get("runtime", {})
    verified = output.get("verifiedFindings", [])
    rejected = output.get("rejectedFindings", [])
    needs = output.get("needsMoreEvidenceFindings", [])

    print("Cyber Swarm findings summary")
    if activation:
        print("  Activation (playbooks supplement routing, not execution plan):")
        print(f"    playbooksRouted: {activation.get('skillsRouted', 0)}")
        print(f"    specialistsPlanned: {activation.get('agentsPlanned', 0)}")
        print(f"    specialistsRun: {activation.get('agentsRun', 0)}")
        agent_types = activation.get("agentTypes", [])
        if isinstance(agent_types, list):
            print(
                f"    specialistTypes: {', '.join(agent_types) if agent_types else 'none'}"
            )
        print(f"    findingsVerified: {activation.get('findingsVerified', len(verified))}")
        print(f"    findingsRejected: {activation.get('findingsRejected', len(rejected))}")
    print(f"  Verified: {len(verified)}")
    print(f"  Rejected: {len(rejected)}")
    print(f"  Needs evidence: {len(needs)}")
    if runtime:
        print(
            "  Runtime: "
            f"provider={runtime.get('provider', 'unknown')} "
            f"model={runtime.get('model', 'unknown')} "
            f"mode={runtime.get('mode', 'full')} "
            f"latency={runtime.get('latencyMode', 'n/a')} "
            f"elapsedMs={runtime.get('elapsedMs', 'n/a')}"
        )
        cache = runtime.get("cache", {})
        if isinstance(cache, dict) and cache.get("scanHash"):
            hit = cache.get("hit")
            print(f"  Cache: {'hit' if hit else 'miss'}  scanHash={cache.get('scanHash')}")
        llm_cache = runtime.get("llmCache", {})
        if isinstance(llm_cache, dict) and llm_cache:
            print(f"  LLM cache: {'hit' if llm_cache.get('hit') else 'miss'}")
            if llm_cache.get("evidenceHash"):
                print(f"  Stable evidence hash: {llm_cache.get('evidenceHash')}")
            if llm_cache.get("cacheKeyPrefix"):
                print(f"  LLM cache key prefix: {llm_cache.get('cacheKeyPrefix')}")
            if llm_cache.get("inputTokenEstimate") is not None:
                print(f"  Input token estimate: {llm_cache.get('inputTokenEstimate')}")
            if llm_cache.get("outputTokens") is not None:
                print(f"  Output tokens: {llm_cache.get('outputTokens')}")
            if llm_cache.get("modelLatencyMs") is not None:
                print(f"  Model latency: {llm_cache.get('modelLatencyMs')} ms")
            if llm_cache.get("outputTokenWarning"):
                print(f"  Warning: {llm_cache.get('outputTokenWarning')}")
        calls = runtime.get("providerCalls", [])
        if isinstance(cache, dict) and cache.get("hit"):
            print("  Model calls: 0")
        elif isinstance(calls, list) and calls:
            total_tokens = sum(
                int(item.get("totalTokens") or 0)
                for item in calls
                if isinstance(item, dict)
            )
            print(f"  Model calls: {len(calls)}  Tokens: {total_tokens or 'n/a'}")
        stage_timings = runtime.get("stageTimings", {})
        if isinstance(stage_timings, dict) and stage_timings:
            print("  Stage timings (ms):")
            for stage in (
                "evidence_pack_build",
                "attack_graph_build",
                "deterministic_draft_generation",
                "llm_prompt_build",
                "llm_call",
                "verification",
                "ranking",
                "report_write",
            ):
                if stage in stage_timings:
                    print(f"    {stage}: {stage_timings[stage]}")
    if verifier:
        print(
            "  Verifier: "
            f"reviewed={verifier.get('reviewedDraftCount', 0)} "
            f"verified={verifier.get('verifiedCount', 0)} "
            f"rejected={verifier.get('rejectedCount', 0)}"
        )
    severity_counts = ranking.get("severityCounts")
    if isinstance(severity_counts, dict):
        print(
            "  Severity: "
            + ", ".join(f"{key}={value}" for key, value in severity_counts.items() if value)
            or "none"
        )
    if len(verified) == 0:
        demo_llm = metrics.get("specialist_agents", {}).get("demoLlm", {})
        if isinstance(demo_llm, dict) and demo_llm.get("fallbackReason"):
            print(f"  Demo LLM: {demo_llm.get('fallbackReason')}")
        if isinstance(demo_llm, dict) and demo_llm.get("mode") == "fallback":
            print(f"  Demo LLM fallback: {demo_llm.get('error', 'LLM unavailable')}")
        print_rejection_diagnostics(output)


def run_bridge(
    scan_report_path: Path,
    routed_skills_path: Path,
    output_path: Path,
    *,
    runtime_config: RuntimeConfig | None = None,
) -> dict:
    config = runtime_config or RuntimeConfig()
    scan_hash = scan_content_hash(scan_report_path)

    if config.from_cache:
        cached = find_cached_findings(
            output_path.parent,
            scan_hash=scan_hash,
            mode=config.mode,
            provider=config.provider,
            model=config.model,
        )
        if cached is None:
            raise CacheReplayError(CACHE_MISS_MESSAGE)

        started = time.perf_counter()
        output = copy_cached_findings(
            cached,
            output_path,
            scan_hash=scan_hash,
            mode=config.mode,
            provider=config.provider,
            model=config.model,
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        metrics = dict(output.get("metrics", {}))
        runtime = dict(metrics.get("runtime", {}))
        runtime["elapsedMs"] = elapsed_ms
        metrics["runtime"] = runtime
        output["metrics"] = metrics
        write_json(output_path, output)
        write_markdown_report(str(output_path), output)
        _print_summary(output)
        return output

    started = time.perf_counter()
    output = run_workflow(
        scan_report_path,
        routed_skills_path,
        output_path,
        runtime_config=config,
        scan_hash=scan_hash,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    metrics = dict(output.get("metrics", {}))
    runtime = dict(metrics.get("runtime", {}))
    runtime["elapsedMs"] = elapsed_ms
    metrics["runtime"] = runtime
    metrics = write_cache_metadata(
        metrics,
        scan_hash=scan_hash,
        hit=False,
        mode=config.mode,
        provider=config.provider,
        model=config.model,
    )
    output["metrics"] = metrics
    write_json(output_path, output)
    write_markdown_report(str(output_path), output)
    _print_summary(output)
    return output
