"""Graph-backed evidence requirements for verified findings."""

from __future__ import annotations

from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.attack_graph import AttackGraph

_GRAPH_REQUIRED_CLASSES = frozenset(
    {
        "broken-access-control",
        "bola",
        "privilege-escalation",
        "api-abuse",
        "ai-action-abuse",
    }
)


def graph_backed_evidence_failures(
    draft: AgentFindingDraft,
    attack_graph: AttackGraph | None,
) -> list[str]:
    if draft.vulnerability_class == "secret-exposure":
        return []

    if draft.vulnerability_class in _GRAPH_REQUIRED_CLASSES:
        if draft.graph_path is None:
            return ["cross-file finding missing graph_path (source node, sink node, trust boundary)"]
        if attack_graph is not None and len(draft.evidence) < 2:
            return ["graph-backed finding requires evidence refs from multiple graph nodes"]

    if draft.graph_path is None:
        return []

    if attack_graph is None:
        return []

    failures: list[str] = []
    source = attack_graph.node_by_id(draft.graph_path.source_node_id)
    sink = attack_graph.node_by_id(draft.graph_path.sink_node_id)
    if source is None:
        failures.append(f"unknown graph source node: {draft.graph_path.source_node_id}")
    if sink is None:
        failures.append(f"unknown graph sink node: {draft.graph_path.sink_node_id}")

    if draft.graph_path.edge_ids:
        known_edges = {edge.id for edge in attack_graph.edges}
        for edge_id in draft.graph_path.edge_ids:
            if edge_id not in known_edges:
                failures.append(f"unknown graph edge: {edge_id}")

    if not draft.graph_path.trust_boundary_crossed.strip():
        failures.append("graph_path missing trust_boundary_crossed")

    return failures
