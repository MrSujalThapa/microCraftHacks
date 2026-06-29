"""Deterministic LangGraph stub nodes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyber_swarm.schemas.io import load_json, write_json
from cyber_swarm.schemas.output import build_empty_output
from cyber_swarm.graph.state import GraphState


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def load_input(state: GraphState) -> GraphState:
    scan_report_path = Path(state["scan_report_path"])
    routed_skills_path = Path(state["routed_skills_path"])

    scan_report = load_json(scan_report_path)
    routed_skills = load_json(routed_skills_path)
    selected = routed_skills.get("selected", [])

    return {
        **state,
        "scan_report": scan_report,
        "routed_skills": routed_skills,
        "draft_findings": [],
        "verified_findings": [],
        "rejected_findings": [],
        "metrics": _merge_metrics(
            state,
            "load_input",
            {
                "status": "completed",
                "routedSkillCount": len(selected) if isinstance(selected, list) else 0,
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
            },
        ),
    }


def verifier_stub(state: GraphState) -> GraphState:
    draft_findings = state.get("draft_findings", [])

    return {
        **state,
        "verified_findings": [],
        "rejected_findings": [],
        "metrics": _merge_metrics(
            state,
            "verifier_stub",
            {
                "status": "completed",
                "verifiedFindingCount": 0,
                "rejectedFindingCount": 0,
                "reviewedDraftCount": len(draft_findings)
                if isinstance(draft_findings, list)
                else 0,
            },
        ),
    }


def report_stub(state: GraphState) -> GraphState:
    scan_report = state.get("scan_report", {})
    scan_report_path = Path(state["scan_report_path"])
    output_path = Path(state["output_path"])

    output = build_empty_output(
        scan_report,
        scan_report_path,
        metrics={
            **state.get("metrics", {}),
            "graph": "langgraph",
            "stages": [
                "load_input",
                "recon_stub",
                "specialist_stub",
                "verifier_stub",
                "report_stub",
            ],
        },
    )

    write_json(output_path, output)

    return {
        **state,
        "output": output,
        "metrics": output["metrics"],
    }
