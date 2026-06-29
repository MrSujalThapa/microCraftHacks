"""LangGraph nodes for the agentic retrieval loop."""

from __future__ import annotations

from typing import Any

from cyber_swarm.graph.state import GraphState
from cyber_swarm.models.retrieval import RetrievedContext, RetrievalQuery
from cyber_swarm.rag.loop import (
    MAX_RETRIEVAL_ITERATIONS,
    finalize_context,
    grade_context,
    plan_retrieval,
    retrieve_for_query,
    rewrite_query,
    serialize_context,
)


def _merge_metrics(state: GraphState, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(state.get("metrics", {}))
    metrics[stage] = payload
    return metrics


def _get_runtime_input(state: GraphState):
    runtime_input = state.get("runtime_input")
    if runtime_input is None:
        raise RuntimeError("runtime_input is required before retrieval nodes run")
    return runtime_input


def plan_retrieval_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    iteration = state.get("retrieval_iteration", 0) + 1
    query = plan_retrieval(runtime_input, iteration=iteration)

    return {
        **state,
        "retrieval_iteration": iteration,
        "current_query": query,
        "retrieval_queries": [*state.get("retrieval_queries", []), query],
        "retrieval_sufficient": False,
        "metrics": _merge_metrics(
            state,
            "plan_retrieval",
            {
                "status": "completed",
                "query": query.query,
                "target": query.target,
                "iteration": iteration,
            },
        ),
    }


def retrieve_context_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    current_query = state.get("current_query")
    if current_query is None:
        raise RuntimeError("current_query is required before retrieve_context runs")

    results = retrieve_for_query(current_query, runtime_input)
    merged = [*state.get("retrieved_context", []), *results]

    return {
        **state,
        "retrieved_context": merged,
        "metrics": _merge_metrics(
            state,
            "retrieve_context",
            {
                "status": "completed",
                "queryId": current_query.id,
                "resultCount": len(results),
            },
        ),
    }


def grade_context_node(state: GraphState) -> GraphState:
    retrieved = state.get("retrieved_context", [])
    decision = grade_context(retrieved)
    attempts = [
        *state.get("retrieval_attempts", []),
        {
            "iteration": state.get("retrieval_iteration", 1),
            "queryId": getattr(state.get("current_query"), "id", None),
            **decision,
        },
    ]

    return {
        **state,
        "retrieval_sufficient": decision["sufficient"],
        "retrieval_attempts": attempts,
        "metrics": _merge_metrics(state, "grade_context", {"status": "completed", **decision}),
    }


def rewrite_query_node(state: GraphState) -> GraphState:
    runtime_input = _get_runtime_input(state)
    current_query = state.get("current_query")
    if current_query is None:
        raise RuntimeError("current_query is required before rewrite_query runs")

    next_query = rewrite_query(current_query, runtime_input)
    iteration = state.get("retrieval_iteration", 1) + 1

    return {
        **state,
        "retrieval_iteration": iteration,
        "current_query": next_query,
        "retrieval_queries": [*state.get("retrieval_queries", []), next_query],
        "retrieval_sufficient": False,
        "metrics": _merge_metrics(
            state,
            "rewrite_query",
            {
                "status": "completed",
                "query": next_query.query,
                "target": next_query.target,
                "iteration": iteration,
            },
        ),
    }


def finalize_context_node(state: GraphState) -> GraphState:
    selected = finalize_context(state.get("retrieved_context", []))

    return {
        **state,
        "selected_context": selected,
        "metrics": _merge_metrics(
            state,
            "finalize_context",
            {
                "status": "completed",
                "selectedCount": len(selected),
                "selectedSources": [item.source_path for item in selected if item.source_path],
            },
        ),
    }


def should_continue_retrieval(state: GraphState) -> str:
    if state.get("retrieval_sufficient"):
        return "finalize_context"
    if state.get("retrieval_iteration", 1) >= MAX_RETRIEVAL_ITERATIONS:
        return "finalize_context"
    return "rewrite_query"
