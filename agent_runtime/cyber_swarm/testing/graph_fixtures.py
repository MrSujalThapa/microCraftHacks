"""Shared graph path fixtures for tests."""

from __future__ import annotations

from cyber_swarm.models.attack_graph import GraphPathRef


def sample_graph_path() -> GraphPathRef:
    return GraphPathRef(
        source_node_id="src-auth-ts-route-login-12",
        sink_node_id="src-auth-ts-handler-login-14",
        trust_boundary_crossed="request -> handler",
        attacker_controlled_input=None,
        missing_guard="requireAuth middleware",
        edge_ids=["edge-route-handler"],
        path_description="route /api/login (src/auth.ts:12) -> handler login (src/auth.ts:14)",
    )
