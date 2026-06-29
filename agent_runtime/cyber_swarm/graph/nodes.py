"""Deterministic LangGraph stub nodes."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from cyber_swarm.schemas.io import write_json
from cyber_swarm.schemas.output import build_output
from cyber_swarm.graph.state import GraphState
from cyber_swarm.rag.loop import serialize_context
from cyber_swarm.rag.normalize import normalize_runtime_input


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def load_input(state: GraphState) -> GraphState:
    scan_report_path = Path(state["scan_report_path"])
    routed_skills_path = Path(state["routed_skills_path"])

    runtime_input = normalize_runtime_input(scan_report_path, routed_skills_path)

    return {
        **state,
        "runtime_input": runtime_input,
        "scan_report": {
            "version": runtime_input.repo.version,
            "scannedAt": runtime_input.repo.scanned_at,
            "projectRoot": runtime_input.repo.project_root,
            "inventory": {
                "totalFiles": runtime_input.repo.inventory.total_files,
                "byCategory": runtime_input.repo.inventory.by_category,
                "files": [
                    {"path": item.path, "category": item.category}
                    for item in runtime_input.repo.inventory.files
                ],
            },
            "stack": [
                {
                    "name": item.name,
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                }
                for item in runtime_input.repo.stack
            ],
            "surfaces": {
                "routes": [
                    {
                        "path": route.path,
                        "file": route.file,
                        **({"framework": route.framework} if route.framework else {}),
                    }
                    for route in runtime_input.repo.surfaces.routes
                ],
                "api": [
                    {
                        "path": route.path,
                        "file": route.file,
                        **({"framework": route.framework} if route.framework else {}),
                    }
                    for route in runtime_input.repo.surfaces.api
                ],
                "auth": [
                    {
                        "file": auth.file,
                        **({"type": auth.type} if auth.type else {}),
                    }
                    for auth in runtime_input.repo.surfaces.auth
                ],
                "dataModels": [
                    {
                        "file": model.file,
                        **({"name": model.name} if model.name else {}),
                    }
                    for model in runtime_input.repo.surfaces.data_models
                ],
            },
        },
        "routed_skills": {
            "reportPath": runtime_input.routed_skills.report_path,
            "routedAt": runtime_input.routed_skills.routed_at,
            "selected": [
                {
                    "name": skill.name,
                    "path": skill.path,
                    "score": skill.score,
                    "reasons": skill.reasons,
                    "agentTypes": skill.agent_types,
                }
                for skill in runtime_input.routed_skills.selected
            ],
        },
        "draft_findings": [],
        "verified_findings": [],
        "rejected_findings": [],
        "metrics": _merge_metrics(
            state,
            "load_input",
            {
                "status": "completed",
                "routedSkillCount": len(runtime_input.routed_skills.selected),
                "normalized": True,
            },
        ),
    }


def recon_stub(state: GraphState) -> GraphState:
    scan_report = state.get("scan_report", {})
    stack = scan_report.get("stack", [])
    inventory = scan_report.get("inventory", {})

    return {
        **state,
        "metrics": _merge_metrics(
            state,
            "recon_stub",
            {
                "status": "completed",
                "stackCount": len(stack) if isinstance(stack, list) else 0,
                "fileCount": inventory.get("totalFiles", 0)
                if isinstance(inventory, dict)
                else 0,
            },
        ),
    }


def specialist_stub(state: GraphState) -> GraphState:
    routed_skills = state.get("routed_skills", {})
    selected = routed_skills.get("selected", [])
    selected_context = state.get("selected_context", [])
    agent_types = sorted(
        {
            agent_type
            for skill in selected
            if isinstance(skill, dict)
            for agent_type in skill.get("agentTypes", [])
            if isinstance(agent_type, str)
        }
    )

    return {
        **state,
        "draft_findings": [],
        "metrics": _merge_metrics(
            state,
            "specialist_stub",
            {
                "status": "completed",
                "draftFindingCount": 0,
                "agentTypes": agent_types,
                "selectedContextCount": len(selected_context),
            },
        ),
    }


def verifier_stub(state: GraphState) -> GraphState:
    draft_findings = state.get("draft_findings", [])
    rejected_findings = state.get("rejected_findings", [])

    return {
        **state,
        "verified_findings": [],
        "metrics": _merge_metrics(
            state,
            "verifier_stub",
            {
                "status": "completed",
                "verifiedFindingCount": 0,
                "rejectedFindingCount": len(rejected_findings),
                "reviewedDraftCount": len(draft_findings),
                "note": "Draft findings retained for later verification phase",
            },
        ),
    }


def report_stub(state: GraphState) -> GraphState:
    scan_report = state.get("scan_report", {})
    scan_report_path = Path(state["scan_report_path"])
    output_path = Path(state["output_path"])

    from cyber_swarm.models.agents import RejectedFindingDraft

    agent_rejected = [
        asdict(item) | {"source": "agent"}
        for item in state.get("rejected_findings", [])
        if isinstance(item, RejectedFindingDraft)
    ]
    verifier_rejected = [
        asdict(item)
        for item in state.get("verifier_rejected_findings", [])
    ]
    needs_evidence = [
        asdict(item)
        for item in state.get("needs_evidence_findings", [])
    ]

    output = build_output(
        scan_report,
        scan_report_path,
        metrics={
            **state.get("metrics", {}),
            "graph": "langgraph",
            "stages": [
                "load_input",
                "plan_retrieval",
                "retrieve_context",
                "grade_context",
                "rewrite_query",
                "finalize_context",
                "recon_agent",
                "attack_planner",
                "specialist_agents",
                "verifier",
                "dedup",
                "report_stub",
            ],
            "retrieval": {
                "attempts": state.get("retrieval_attempts", []),
                "selectedContext": serialize_context(state.get("selected_context", [])),
            },
            "agents": {
                "recon": asdict(state["recon_report"]) if state.get("recon_report") else None,
                "attackPlanner": {
                    "hypotheses": [
                        asdict(item) for item in state.get("attack_hypotheses", [])
                    ],
                },
                "specialists": {
                    "draftFindings": [
                        asdict(item) for item in state.get("draft_findings", [])
                    ],
                    "rejectedDrafts": [
                        asdict(item) for item in state.get("rejected_findings", [])
                        if isinstance(item, RejectedFindingDraft)
                    ],
                },
            },
        },
        verified_findings=state.get("verified_findings", []),
        rejected_findings=[*agent_rejected, *verifier_rejected],
        needs_evidence_findings=needs_evidence,
    )

    write_json(output_path, output)

    return {
        **state,
        "output": output,
        "metrics": output["metrics"],
    }
