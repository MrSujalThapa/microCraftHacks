"""LangGraph workflow assembly and execution."""

from __future__ import annotations

from pathlib import Path

from langgraph.graph import END, START, StateGraph

from cyber_swarm.graph.agent_nodes import (
    attack_planner_node,
    recon_agent_node,
    specialist_agents_node,
)
from cyber_swarm.graph.nodes import (
    load_input,
    report_stub,
)
from cyber_swarm.graph.verifier_nodes import dedup_node, rank_node, verifier_node
from cyber_swarm.graph.rag_nodes import (
    finalize_context_node,
    grade_context_node,
    plan_retrieval_node,
    retrieve_context_node,
    rewrite_query_node,
    should_continue_retrieval,
)
from cyber_swarm.graph.state import GraphState


def build_workflow():
    graph = StateGraph(GraphState)

    graph.add_node("load_input", load_input)
    graph.add_node("plan_retrieval", plan_retrieval_node)
    graph.add_node("retrieve_context", retrieve_context_node)
    graph.add_node("grade_context", grade_context_node)
    graph.add_node("rewrite_query", rewrite_query_node)
    graph.add_node("finalize_context", finalize_context_node)
    graph.add_node("recon_agent", recon_agent_node)
    graph.add_node("attack_planner", attack_planner_node)
    graph.add_node("specialist_agents", specialist_agents_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("dedup", dedup_node)
    graph.add_node("rank", rank_node)
    graph.add_node("report_stub", report_stub)

    graph.add_edge(START, "load_input")
    graph.add_edge("load_input", "plan_retrieval")
    graph.add_edge("plan_retrieval", "retrieve_context")
    graph.add_edge("retrieve_context", "grade_context")
    graph.add_conditional_edges(
        "grade_context",
        should_continue_retrieval,
        {
            "rewrite_query": "rewrite_query",
            "finalize_context": "finalize_context",
        },
    )
    graph.add_edge("rewrite_query", "retrieve_context")
    graph.add_edge("finalize_context", "recon_agent")
    graph.add_edge("recon_agent", "attack_planner")
    graph.add_edge("attack_planner", "specialist_agents")
    graph.add_edge("specialist_agents", "verifier")
    graph.add_edge("verifier", "dedup")
    graph.add_edge("dedup", "rank")
    graph.add_edge("rank", "report_stub")
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
            "retrieval_queries": [],
            "retrieved_context": [],
            "selected_context": [],
            "retrieval_attempts": [],
            "retrieval_iteration": 0,
            "retrieval_sufficient": False,
            "attack_hypotheses": [],
        }
    )
    output = final_state.get("output")
    if not isinstance(output, dict):
        raise RuntimeError("LangGraph workflow did not produce output")
    return output
