"""Model-backed agent stages for smoke testing."""

from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

from cyber_swarm.agents.attack_planner import run_attack_planner
from cyber_swarm.agents.recon import run_recon
from cyber_swarm.models.agents import (
    AttackHypothesis,
    HighRiskSurface,
    ReconReport,
    TrustBoundary,
)
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.providers.base import AgentProvider
from cyber_swarm.providers.prompts import BASELINE_SYSTEM_PROMPT


def _context_excerpt(context: list[RetrievedContext], limit: int = 8) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in context[:limit]:
        items.append(
            {
                "id": item.id,
                "path": item.source_path,
                "category": item.context_category,
                "score": item.score,
                "excerpt": item.excerpt[:400],
            }
        )
    return items


def _scan_summary(runtime_input: RuntimeInput) -> dict[str, Any]:
    repo = runtime_input.repo
    return {
        "projectRoot": repo.project_root,
        "stack": [{"name": item.name, "confidence": item.confidence} for item in repo.stack[:6]],
        "routes": [
            {"path": route.path, "file": route.file}
            for route in [*repo.surfaces.routes, *repo.surfaces.api][:12]
        ],
        "authFiles": [auth.file for auth in repo.surfaces.auth[:8]],
        "inventoryCount": repo.inventory.total_files,
    }


def run_recon_with_provider(
    provider: AgentProvider,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
) -> tuple[ReconReport, dict[str, Any]]:
    fallback = run_recon(runtime_input, selected_context)
    user = json.dumps(
        {
            "task": "recon",
            "scan": _scan_summary(runtime_input),
            "selectedContext": _context_excerpt(selected_context),
            "responseSchema": {
                "trust_boundaries": [
                    {
                        "boundary_type": "string",
                        "description": "string",
                        "files": ["string"],
                        "routes": ["string"],
                    }
                ],
                "high_risk_surfaces": [
                    {
                        "surface_type": "string",
                        "path": "string",
                        "file": "string",
                        "reason": "string",
                    }
                ],
                "selected_agent_targets": ["auth", "api", "secrets"],
            },
        },
        indent=2,
    )
    try:
        result = provider.complete_json(system=BASELINE_SYSTEM_PROMPT, user=user, purpose="recon")
        recon = _parse_recon_payload(result.payload, fallback)
        return recon, {"mode": "openai", "call": asdict(result)}
    except Exception as error:  # noqa: BLE001 - smoke path falls back safely
        return fallback, {"mode": "fallback", "error": str(error)}


def run_attack_planner_with_provider(
    provider: AgentProvider,
    runtime_input: RuntimeInput,
    recon: ReconReport,
    selected_context: list[RetrievedContext],
    *,
    max_hypotheses: int = 3,
) -> tuple[list[AttackHypothesis], dict[str, Any]]:
    fallback = run_attack_planner(runtime_input, recon, selected_context)[:max_hypotheses]
    user = json.dumps(
        {
            "task": "attack_planner",
            "recon": {
                "trust_boundaries": [boundary.__dict__ for boundary in recon.trust_boundaries],
                "high_risk_surfaces": [surface.__dict__ for surface in recon.high_risk_surfaces],
                "selected_agent_targets": recon.selected_agent_targets,
            },
            "selectedContext": _context_excerpt(selected_context),
            "maxHypotheses": max_hypotheses,
            "responseSchema": {
                "hypotheses": [
                    {
                        "id": "string",
                        "agent_type": "auth|api|secrets",
                        "specialist": "string",
                        "title": "string",
                        "vulnerability_class": "string",
                        "target_surfaces": ["string"],
                        "target_files": ["string"],
                        "reasoning": "string",
                        "required_evidence": ["string"],
                        "priority": "high|medium|low",
                    }
                ]
            },
        },
        indent=2,
    )
    try:
        result = provider.complete_json(
            system=BASELINE_SYSTEM_PROMPT,
            user=user,
            purpose="attack_planner",
        )
        hypotheses = _parse_hypotheses_payload(result.payload, fallback, max_hypotheses)
        return hypotheses, {"mode": "openai", "call": asdict(result)}
    except Exception as error:  # noqa: BLE001
        return fallback, {"mode": "fallback", "error": str(error)}


def run_verifier_review_with_provider(
    provider: AgentProvider,
    drafts: list[Any],
    scan_report: dict[str, Any],
    *,
    max_drafts: int = 3,
) -> dict[str, Any]:
    draft_payload = []
    for draft in drafts[:max_drafts]:
        draft_payload.append(
            {
                "id": getattr(draft, "id", "unknown"),
                "title": getattr(draft, "title", "unknown"),
                "vulnerability_class": getattr(draft, "vulnerability_class", "unknown"),
                "claim": getattr(draft, "claim", ""),
                "affected_surfaces": getattr(draft, "affected_surfaces", []),
                "confidence": getattr(draft, "confidence", "medium"),
            }
        )

    user = json.dumps(
        {
            "task": "verifier_review",
            "drafts": draft_payload,
            "scanSummary": {
                "routeCount": len(scan_report.get("surfaces", {}).get("api", []))
                + len(scan_report.get("surfaces", {}).get("routes", [])),
                "inventoryCount": scan_report.get("inventory", {}).get("totalFiles", 0),
            },
            "responseSchema": {
                "reviews": [
                    {
                        "draft_id": "string",
                        "recommendation": "verify|reject|needs_more_evidence",
                        "rationale": "string",
                        "safe_static_only": True,
                    }
                ]
            },
        },
        indent=2,
    )
    try:
        result = provider.complete_json(
            system=BASELINE_SYSTEM_PROMPT,
            user=user,
            purpose="verifier",
        )
        return {"mode": "openai", "call": asdict(result), "review": result.payload}
    except Exception as error:  # noqa: BLE001
        return {"mode": "fallback", "error": str(error)}


def _parse_recon_payload(payload: dict[str, Any], fallback: ReconReport) -> ReconReport:
    boundaries = []
    for item in payload.get("trust_boundaries", []):
        if not isinstance(item, dict):
            continue
        boundaries.append(
            TrustBoundary(
                boundary_type=str(item.get("boundary_type", "unknown")),
                description=str(item.get("description", "")),
                files=[str(path) for path in item.get("files", []) if isinstance(path, str)],
                routes=[str(route) for route in item.get("routes", []) if isinstance(route, str)],
            )
        )

    surfaces = []
    for item in payload.get("high_risk_surfaces", []):
        if not isinstance(item, dict):
            continue
        surfaces.append(
            HighRiskSurface(
                surface_type=str(item.get("surface_type", "unknown")),
                path=str(item.get("path", "")),
                file=str(item.get("file", "")),
                reason=str(item.get("reason", "")),
            )
        )

    targets = [
        str(target)
        for target in payload.get("selected_agent_targets", [])
        if isinstance(target, str)
    ]

    if not boundaries and not surfaces and not targets:
        return fallback

    return ReconReport(
        trust_boundaries=boundaries or fallback.trust_boundaries,
        high_risk_surfaces=surfaces or fallback.high_risk_surfaces,
        selected_agent_targets=targets or fallback.selected_agent_targets,
    )


def _parse_hypotheses_payload(
    payload: dict[str, Any],
    fallback: list[AttackHypothesis],
    max_hypotheses: int,
) -> list[AttackHypothesis]:
    parsed: list[AttackHypothesis] = []
    for item in payload.get("hypotheses", []):
        if not isinstance(item, dict):
            continue
        parsed.append(
            AttackHypothesis(
                id=str(item.get("id", f"hyp-{len(parsed) + 1}")),
                agent_type=str(item.get("agent_type", "api")),
                specialist=str(item.get("specialist", "api-abuse")),
                title=str(item.get("title", "Security hypothesis")),
                vulnerability_class=str(item.get("vulnerability_class", "security-misconfiguration")),
                target_surfaces=[
                    str(surface) for surface in item.get("target_surfaces", []) if isinstance(surface, str)
                ],
                target_files=[str(path) for path in item.get("target_files", []) if isinstance(path, str)],
                reasoning=str(item.get("reasoning", "")),
                required_evidence=[
                    str(value) for value in item.get("required_evidence", []) if isinstance(value, str)
                ],
                priority=item.get("priority", "medium"),  # type: ignore[arg-type]
            )
        )
        if len(parsed) >= max_hypotheses:
            break

    return parsed or fallback
