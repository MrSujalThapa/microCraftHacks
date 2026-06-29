"""LangGraph workflow assembly and execution."""

from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, START, StateGraph

from cyber_swarm.graph.nodes import (
    load_input,
    recon_stub,
    report_stub,
    specialist_stub,
    verifier_stub,
)
from cyber_swarm.graph.state import GraphState


def build_workflow():
    graph = StateGraph(GraphState)

    graph.add_node("load_input", load_input)
    graph.add_node("recon_stub", recon_stub)
    graph.add_node("specialist_stub", specialist_stub)
    graph.add_node("verifier_stub", verifier_stub)
    graph.add_node("report_stub", report_stub)

    graph.add_edge(START, "load_input")
    graph.add_edge("load_input", "recon_stub")
    graph.add_edge("recon_stub", "specialist_stub")
    graph.add_edge("specialist_stub", "verifier_stub")
    graph.add_edge("verifier_stub", "report_stub")
    graph.add_edge("report_stub", END)

    return graph.compile()


def run_workflow(scan_report_path: Path, routed_skills_path: Path, output_path: Path) -> dict:
    workflow = build_workflow()
    final_state = workflow.invoke(
        {
            "scan_report_path": str(scan_report_path),
            "routed_skills_path": str(routed_skills_path),
            "output_path": str(output_path),
            "metrics": {},
        }
    )
    output = final_state.get("output")
    if not isinstance(output, dict):
        raise RuntimeError("LangGraph workflow did not produce output")
    return output
