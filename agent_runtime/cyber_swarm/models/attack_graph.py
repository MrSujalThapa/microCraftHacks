"""Static attack graph models for cross-file vulnerability reasoning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

NodeType = Literal[
    "route",
    "handler",
    "auth_guard",
    "param_input",
    "data_access",
    "storage_op",
    "ai_action",
    "config_secret",
    "client_call",
]

EdgeType = Literal[
    "routes_to",
    "guarded_by",
    "missing_guard",
    "accepts_input",
    "accesses",
    "calls",
    "crosses_boundary",
    "configures",
    "frontend_trust",
]


@dataclass(frozen=True)
class AttackGraphNode:
    id: str
    node_type: NodeType
    label: str
    path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    route: str | None = None
    symbol: str | None = None
    evidence_pack_id: str | None = None


@dataclass(frozen=True)
class AttackGraphEdge:
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str


@dataclass(frozen=True)
class AttackGraph:
    nodes: list[AttackGraphNode] = field(default_factory=list)
    edges: list[AttackGraphEdge] = field(default_factory=list)

    def node_by_id(self, node_id: str) -> AttackGraphNode | None:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def edges_from(self, node_id: str) -> list[AttackGraphEdge]:
        return [edge for edge in self.edges if edge.source_id == node_id]

    def edges_to(self, node_id: str) -> list[AttackGraphEdge]:
        return [edge for edge in self.edges if edge.target_id == node_id]

    def slice_for_specialist(self, specialist: str) -> AttackGraph:
        """Return subgraph relevant to a specialist agent."""
        allowed_nodes: set[str] = set()
        allowed_types: set[str]

        if specialist in {"auth-boundary", "auth-breaker"}:
            allowed_types = {"route", "handler", "auth_guard", "param_input", "client_call"}
        elif specialist == "object-ownership":
            allowed_types = {"route", "handler", "param_input", "data_access", "auth_guard"}
        elif specialist == "api-abuse":
            allowed_types = {"route", "handler", "param_input", "data_access", "auth_guard"}
        elif specialist == "storage-access":
            allowed_types = {"route", "handler", "storage_op", "param_input", "auth_guard", "data_access"}
        elif specialist == "ai-action-boundary":
            allowed_types = {"route", "handler", "ai_action", "param_input", "auth_guard"}
        elif specialist == "secrets-config":
            allowed_types = {"config_secret", "handler", "route", "data_access"}
        else:
            return self

        for node in self.nodes:
            if node.node_type in allowed_types:
                allowed_nodes.add(node.id)

        for edge in self.edges:
            if edge.source_id in allowed_nodes:
                allowed_nodes.add(edge.target_id)
            if edge.target_id in allowed_nodes:
                allowed_nodes.add(edge.source_id)

        nodes = [node for node in self.nodes if node.id in allowed_nodes]
        node_ids = {node.id for node in nodes}
        edges = [
            edge
            for edge in self.edges
            if edge.source_id in node_ids and edge.target_id in node_ids
        ]
        return AttackGraph(nodes=nodes, edges=edges)


@dataclass(frozen=True)
class GraphPathRef:
    source_node_id: str
    sink_node_id: str
    trust_boundary_crossed: str
    attacker_controlled_input: str | None
    missing_guard: str | None
    edge_ids: list[str]
    path_description: str
