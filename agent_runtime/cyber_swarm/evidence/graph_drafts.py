"""Build graph-backed specialist drafts from attack graph paths."""

from __future__ import annotations

from cyber_swarm.agents.shared import skills_for_agent, static_reproduction
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.attack_graph import AttackGraph, AttackGraphEdge, AttackGraphNode, GraphPathRef
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput

_SENSITIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _pack_for_node(
    node: AttackGraphNode,
    packs: list[EvidencePack],
) -> EvidencePack | None:
    if node.evidence_pack_id:
        for pack in packs:
            if pack.id == node.evidence_pack_id:
                return pack
    for pack in packs:
        if pack.path.replace("\\", "/") == (node.path or "").replace("\\", "/"):
            if pack.line_start == node.line_start:
                return pack
            if node.line_start and pack.line_start <= node.line_start <= pack.line_end:
                return pack
    return None


def _graph_path_from_edge(
    graph: AttackGraph,
    edge: AttackGraphEdge,
    *,
    trust_boundary: str,
    attacker_input: str | None,
    missing_guard: str | None,
) -> GraphPathRef | None:
    source = graph.node_by_id(edge.source_id)
    sink = graph.node_by_id(edge.target_id)
    if source is None or sink is None:
        return None
    return GraphPathRef(
        source_node_id=source.id,
        sink_node_id=sink.id,
        trust_boundary_crossed=trust_boundary,
        attacker_controlled_input=attacker_input,
        missing_guard=missing_guard,
        edge_ids=[edge.id],
        path_description=f"{source.label} ({source.path}:{source.line_start}) -> {sink.label} ({sink.path}:{sink.line_start})",
    )


def _evidence_for_nodes(
    nodes: list[AttackGraphNode],
    packs: list[EvidencePack],
    explanation_prefix: str,
) -> list:
    refs = []
    for node in nodes:
        pack = _pack_for_node(node, packs)
        if pack is None:
            continue
        refs.append(
            evidence_from_pack(
                pack,
                f"{explanation_prefix}: {node.label} at {node.path}:{node.line_start}",
            )
        )
    return refs


def _method_from_handler(handler: AttackGraphNode) -> str:
    label = handler.label.upper()
    for method in _SENSITIVE_METHODS | {"GET"}:
        if label.startswith(method):
            return method
    return "GET"


def build_graph_auth_boundary_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    slice_graph = graph.slice_for_specialist("auth-boundary")
    for edge in slice_graph.edges:
        if edge.edge_type != "missing_guard":
            continue
        handler = slice_graph.node_by_id(edge.source_id)
        missing = slice_graph.node_by_id(edge.target_id)
        if handler is None or missing is None:
            continue
        if handler.route and handler.route.strip().lower() in {"/", "/health", "/api/health", "/status", "/ping"}:
            continue

        evidence = _evidence_for_nodes([handler, missing], evidence_packs, "Auth boundary gap")
        if not evidence:
            continue

        graph_path = _graph_path_from_edge(
            slice_graph,
            edge,
            trust_boundary="request -> handler",
            attacker_input=None,
            missing_guard="auth dependency or guard",
        )
        route = handler.route or hypothesis.target_surfaces[0] if hypothesis.target_surfaces else "/api/route"
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"Sensitive route {route} lacks auth guard on {handler.path}",
            vulnerability_class="broken-access-control",
            claim=(
                f"The {handler.label} handler in {handler.path}:{handler.line_start} exposes {route} "
                "without a visible auth dependency or guard before handler logic executes."
            ),
            affected_surfaces=[route],
            evidence=evidence,
            impact_hypothesis="Unauthenticated requests can reach sensitive handler logic.",
            attack_path=graph_path.path_description if graph_path else edge.label,
            safe_reproduction=static_reproduction(
                [
                    f"Open {handler.path}:{handler.line_start} and inspect {handler.label}.",
                    f"Confirm {route} does not declare auth Depends() or middleware before business logic.",
                ],
                f"Handler for {route} lacks visible auth enforcement.",
            ),
            confidence="high",
            agent_type="auth",
            specialist="auth-boundary",
            selected_skills=skills_for_agent(runtime_input, "auth"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def build_graph_ownership_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    slice_graph = graph.slice_for_specialist("object-ownership")
    for edge in slice_graph.edges:
        if edge.edge_type != "crosses_boundary":
            continue
        if "ownership" not in edge.label.lower():
            continue
        source = slice_graph.node_by_id(edge.source_id)
        sink = slice_graph.node_by_id(edge.target_id)
        if source is None or sink is None:
            continue

        handler = _find_handler_for_node(slice_graph, source.id)
        evidence_nodes = [node for node in (source, sink, handler) if node is not None]
        evidence = _evidence_for_nodes(evidence_nodes, evidence_packs, "Ownership boundary gap")
        if len(evidence) < 2:
            continue

        graph_path = _graph_path_from_edge(
            slice_graph,
            edge,
            trust_boundary="user input -> data access",
            attacker_input=source.label,
            missing_guard="ownership or tenant check",
        )
        route = handler.route if handler and handler.route else hypothesis.target_surfaces[0] if hypothesis.target_surfaces else ""
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"Missing ownership check: {source.label} reaches data access in {sink.path}",
            vulnerability_class="bola",
            claim=(
                f"Attacker-controlled {source.label} in {source.path}:{source.line_start} reaches "
                f"{sink.label} in {sink.path}:{sink.line_start} without a visible ownership or tenant check."
            ),
            affected_surfaces=[route] if route else [],
            evidence=evidence,
            impact_hypothesis="Users may access or modify objects belonging to other accounts (BOLA/IDOR).",
            attack_path=graph_path.path_description if graph_path else edge.label,
            safe_reproduction=static_reproduction(
                [
                    f"Open {source.path}:{source.line_start} and trace {source.label} into {sink.path}.",
                    "Confirm no owner_id or tenant_id comparison guards the data access call.",
                ],
                "User-controlled identifier reaches data layer without ownership validation.",
            ),
            confidence="high",
            agent_type="auth",
            specialist="object-ownership",
            selected_skills=skills_for_agent(runtime_input, "auth"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def build_graph_service_role_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    for node in graph.nodes:
        if node.node_type != "config_secret" or "service_role" not in node.label.lower():
            continue
        handler = _find_handler_for_node(graph, node.id)
        if handler is None:
            continue
        route = handler.route or ""
        if not route:
            continue

        evidence = _evidence_for_nodes([handler, node], evidence_packs, "Service role in request path")
        if len(evidence) < 2:
            continue

        edge = next(
            (item for item in graph.edges if item.source_id == handler.id and item.target_id == node.id),
            None,
        )
        graph_path = (
            _graph_path_from_edge(
                graph,
                edge,
                trust_boundary="request handler -> privileged client",
                attacker_input="HTTP request",
                missing_guard="user-scoped client or RLS",
            )
            if edge
            else GraphPathRef(
                source_node_id=handler.id,
                sink_node_id=node.id,
                trust_boundary_crossed="request handler -> privileged client",
                attacker_controlled_input="HTTP request",
                missing_guard="user-scoped client or RLS",
                edge_ids=[],
                path_description=f"{handler.label} -> {node.label}",
            )
        )

        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"Service-role client reachable from {route} handler in {handler.path}",
            vulnerability_class="privilege-escalation",
            claim=(
                f"The {handler.label} handler in {handler.path}:{handler.line_start} uses a service-role "
                f"or admin Supabase client at {node.path}:{node.line_start}, bypassing row-level security."
            ),
            affected_surfaces=[route],
            evidence=evidence,
            impact_hypothesis="Request handlers using service-role keys can read or write any tenant data.",
            attack_path=graph_path.path_description,
            safe_reproduction=static_reproduction(
                [
                    f"Open {handler.path}:{handler.line_start} and inspect {handler.label}.",
                    f"Confirm {node.path}:{node.line_start} instantiates a service-role client inside the request path.",
                ],
                "Service-role credentials are used in a user-reachable request handler.",
            ),
            confidence="high",
            agent_type="storage",
            specialist="storage-access",
            selected_skills=skills_for_agent(runtime_input, "storage"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def build_graph_ai_action_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    for edge in graph.edges:
        if edge.edge_type != "crosses_boundary" or "AI action" not in edge.label:
            continue
        handler = graph.node_by_id(edge.source_id)
        ai_node = graph.node_by_id(edge.target_id)
        if handler is None or ai_node is None:
            continue

        evidence = _evidence_for_nodes([handler, ai_node], evidence_packs, "AI action boundary gap")
        if len(evidence) < 2:
            continue

        graph_path = _graph_path_from_edge(
            graph,
            edge,
            trust_boundary="request -> AI/tool action",
            attacker_input="request payload",
            missing_guard="approval or tenant boundary",
        )
        route = handler.route or hypothesis.target_surfaces[0] if hypothesis.target_surfaces else "/api/action"
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"AI/tool action on {route} lacks approval gate in {handler.path}",
            vulnerability_class="ai-action-abuse",
            claim=(
                f"The {handler.label} handler in {handler.path}:{handler.line_start} invokes an AI or tool "
                f"action at {ai_node.path}:{ai_node.line_start} without a visible approval or tenant boundary."
            ),
            affected_surfaces=[route],
            evidence=evidence,
            impact_hypothesis="Unapproved AI or tool actions may execute with caller privileges.",
            attack_path=graph_path.path_description if graph_path else edge.label,
            safe_reproduction=static_reproduction(
                [
                    f"Open {handler.path}:{handler.line_start} and trace {handler.label} to the AI call.",
                    f"Confirm {ai_node.path}:{ai_node.line_start} has no approval, role, or tenant guard.",
                ],
                "AI/tool action is reachable from request handler without approval gate.",
            ),
            confidence="high",
            agent_type="ai",
            specialist="ai-action-boundary",
            selected_skills=skills_for_agent(runtime_input, "ai"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def build_graph_frontend_backend_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    for edge in graph.edges:
        if edge.edge_type != "frontend_trust":
            continue
        client = graph.node_by_id(edge.source_id)
        backend_route = graph.node_by_id(edge.target_id)
        if client is None or backend_route is None:
            continue

        backend_handler = _handler_for_route(graph, backend_route.route)
        if backend_handler is None:
            continue

        has_backend_guard = any(
            item.edge_type == "guarded_by" and item.source_id == backend_handler.id for item in graph.edges
        )
        if has_backend_guard:
            continue

        client_auth = _find_auth_in_file(graph, client.path)
        if client_auth is None:
            continue

        evidence = _evidence_for_nodes(
            [client, client_auth, backend_handler, backend_route],
            evidence_packs,
            "Frontend/backend trust mismatch",
        )
        if len(evidence) < 2:
            continue

        graph_path = GraphPathRef(
            source_node_id=client.id,
            sink_node_id=backend_handler.id,
            trust_boundary_crossed="frontend auth gate -> backend handler",
            attacker_controlled_input="direct API request bypassing UI",
            missing_guard="backend auth guard matching frontend session",
            edge_ids=[edge.id],
            path_description=(
                f"{client.label} ({client.path}) expects auth but {backend_handler.label} "
                f"({backend_handler.path}:{backend_handler.line_start}) lacks backend guard"
            ),
        )
        route = backend_route.route or ""
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"Frontend auth gate on {client.path} but backend {route} lacks guard",
            vulnerability_class="broken-access-control",
            claim=(
                f"Frontend {client.path} uses auth hooks but backend handler {backend_handler.label} "
                f"in {backend_handler.path}:{backend_handler.line_start} for {route} lacks a matching auth guard."
            ),
            affected_surfaces=[route] if route else [],
            evidence=evidence,
            impact_hypothesis="Attackers can bypass frontend auth by calling the backend API directly.",
            attack_path=graph_path.path_description,
            safe_reproduction=static_reproduction(
                [
                    f"Open {client.path} and confirm auth hook usage.",
                    f"Open {backend_handler.path}:{backend_handler.line_start} and confirm missing backend guard.",
                ],
                "Backend route is reachable without auth despite frontend session gate.",
            ),
            confidence="high",
            agent_type="auth",
            specialist="auth-boundary",
            selected_skills=skills_for_agent(runtime_input, "auth"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def build_graph_api_abuse_draft(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    graph: AttackGraph,
    evidence_packs: list[EvidencePack],
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    slice_graph = graph.slice_for_specialist("api-abuse")
    for handler in slice_graph.nodes:
        if handler.node_type != "handler" or not handler.route:
            continue
        if handler.route.strip().lower() in {"/", "/health", "/api/health", "/status", "/ping"}:
            continue

        params = [
            node
            for edge in slice_graph.edges
            if edge.source_id == handler.id and edge.edge_type == "accepts_input"
            for node in [slice_graph.node_by_id(edge.target_id)]
            if node is not None
        ]
        sinks = [
            node
            for edge in slice_graph.edges
            if edge.source_id == handler.id and edge.edge_type == "accesses"
            for node in [slice_graph.node_by_id(edge.target_id)]
            if node is not None and node.node_type in {"data_access", "storage_op"}
        ]
        if not params or not sinks:
            continue

        param = params[0]
        sink = sinks[0]
        evidence = _evidence_for_nodes([handler, param, sink], evidence_packs, "Unvalidated input to sensitive sink")
        if len(evidence) < 2:
            continue

        graph_path = GraphPathRef(
            source_node_id=param.id,
            sink_node_id=sink.id,
            trust_boundary_crossed="user input -> sensitive sink",
            attacker_controlled_input=param.label,
            missing_guard="input validation or schema",
            edge_ids=[],
            path_description=f"{handler.label}: {param.label} -> {sink.label} without validation",
        )
        return AgentFindingDraft(
            id=f"draft-{hypothesis.id}",
            title=f"User input reaches sensitive sink on {handler.route} in {handler.path}",
            vulnerability_class="api-abuse",
            claim=(
                f"Attacker-controlled {param.label} in {handler.path}:{handler.line_start} reaches "
                f"{sink.label} at {sink.path}:{sink.line_start} without visible input validation."
            ),
            affected_surfaces=[handler.route],
            evidence=evidence,
            impact_hypothesis="Unvalidated user input may reach database or storage operations.",
            attack_path=graph_path.path_description,
            safe_reproduction=static_reproduction(
                [
                    f"Open {handler.path}:{handler.line_start} and inspect {handler.label}.",
                    f"Trace {param.label} into {sink.path}:{sink.line_start} and confirm missing validation.",
                ],
                "User-controlled input reaches sensitive sink without validation.",
            ),
            confidence="high",
            agent_type="api",
            specialist="api-abuse",
            selected_skills=skills_for_agent(runtime_input, "api"),
            retrieval_trace=[item.id for item in selected_context[:3]],
            graph_path=graph_path,
        )
    return None


def _find_handler_for_node(graph: AttackGraph, node_id: str) -> AttackGraphNode | None:
    visited: set[str] = set()
    queue = [node_id]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for edge in graph.edges:
            if edge.target_id != current:
                continue
            source = graph.node_by_id(edge.source_id)
            if source and source.node_type == "handler":
                return source
            queue.append(edge.source_id)
    return None


def _handler_for_route(graph: AttackGraph, route: str | None) -> AttackGraphNode | None:
    if not route:
        return None
    for node in graph.nodes:
        if node.node_type == "handler" and node.route == route:
            return node
    for edge in graph.edges:
        if edge.edge_type != "routes_to":
            continue
        route_node = graph.node_by_id(edge.source_id)
        handler = graph.node_by_id(edge.target_id)
        if route_node and handler and route_node.route == route:
            return handler
    return None


def _find_auth_in_file(graph: AttackGraph, path: str | None) -> AttackGraphNode | None:
    if not path:
        return None
    normalized = path.replace("\\", "/")
    for node in graph.nodes:
        if node.node_type == "auth_guard" and (node.path or "").replace("\\", "/") == normalized:
            return node
    return None
