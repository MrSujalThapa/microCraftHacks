"""Build static attack graph from scan surfaces and source files."""

from __future__ import annotations

import re
from pathlib import Path

from cyber_swarm.evidence.extract import extract_symbols
from cyber_swarm.evidence.packs import _collect_candidate_paths
from cyber_swarm.evidence.reader import read_lines
from cyber_swarm.models.attack_graph import AttackGraph, AttackGraphEdge, AttackGraphNode
from cyber_swarm.models.repo import RepoIntelligence

_KIND_TO_NODE_TYPE = {
    "route_decorator": "route",
    "route_handler": "handler",
    "function": "handler",
    "dependency": "auth_guard",
    "auth_guard": "auth_guard",
    "auth_helper": "auth_guard",
    "auth_config": "auth_guard",
    "param_input": "param_input",
    "data_access": "data_access",
    "storage_op": "storage_op",
    "storage_client": "storage_op",
    "ai_action": "ai_action",
    "service_role": "config_secret",
    "env_key": "config_secret",
    "client_call": "client_call",
    "hook": "auth_guard",
}

_SENSITIVE_ROUTE = re.compile(
    r"(?i)(user|account|profile|order|document|file|upload|admin|tenant|"
    r"delete|update|create|execute|run|action|tool|storage|media|owner)"
)
_PUBLIC_ROUTE = re.compile(r"(?i)(/health|/ping|/status|^/$|/api/health)")
_OWNER_PARAM = re.compile(r"(?i)(user[_-]?id|owner[_-]?id|account[_-]?id|document[_-]?id|resource[_-]?id|/{[^}]+})")
_APPROVAL = re.compile(r"(?i)(approve|approval|confirm|authorize|require_admin|check_permission)")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return cleaned or "node"


def _node_id(path: str, kind: str, symbol: str, line: int) -> str:
    return f"{_slug(path)}-{_slug(kind)}-{_slug(symbol)}-{line}"


def _edge_id(source: str, target: str, edge_type: str) -> str:
    return f"edge-{_slug(source)}-{_slug(edge_type)}-{_slug(target)}"


def _method_from_route_symbol(symbol: str) -> str:
    return symbol.split()[0].upper() if " " in symbol else "GET"


def _route_from_symbol(symbol: str, route: str | None) -> str | None:
    if route:
        return route
    if " " in symbol:
        return symbol.split(maxsplit=1)[1]
    return None


def build_attack_graph(
    project_root: Path,
    repo: RepoIntelligence,
    context_paths: set[str] | None = None,
    *,
    pack_id_by_location: dict[tuple[str, int], str] | None = None,
) -> AttackGraph:
    """Build attack graph connecting routes, handlers, guards, inputs, and sinks."""
    nodes: list[AttackGraphNode] = []
    edges: list[AttackGraphEdge] = []
    node_index: dict[str, AttackGraphNode] = {}
    pack_lookup = pack_id_by_location or {}

    def add_node(node: AttackGraphNode) -> AttackGraphNode:
        existing = node_index.get(node.id)
        if existing is not None:
            return existing
        node_index[node.id] = node
        nodes.append(node)
        return node

    def add_edge(source_id: str, target_id: str, edge_type: str, label: str) -> None:
        edge = AttackGraphEdge(
            id=_edge_id(source_id, target_id, edge_type),
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,  # type: ignore[arg-type]
            label=label,
        )
        if not any(item.id == edge.id for item in edges):
            edges.append(edge)

    candidate_paths = _collect_candidate_paths(repo, context_paths or set())
    route_nodes_by_file: dict[str, list[AttackGraphNode]] = {}
    handler_nodes_by_file: dict[str, list[AttackGraphNode]] = {}
    auth_nodes_by_file: dict[str, list[AttackGraphNode]] = {}

    for path in candidate_paths:
        if not (project_root / path).is_file():
            continue
        lines = read_lines(project_root, path)
        if not lines:
            continue

        file_routes: list[AttackGraphNode] = []
        file_handlers: list[AttackGraphNode] = []
        file_auth: list[AttackGraphNode] = []
        pending_route: AttackGraphNode | None = None

        for hit in extract_symbols(lines, path):
            node_type = _KIND_TO_NODE_TYPE.get(hit.kind, "handler")
            route = _route_from_symbol(hit.symbol, hit.route)
            if route is None and pending_route is not None:
                route = pending_route.route
            pack_id = pack_lookup.get((path.replace("\\", "/"), hit.line_start))

            node = add_node(
                AttackGraphNode(
                    id=_node_id(path, hit.kind, hit.symbol, hit.line_start),
                    node_type=node_type,  # type: ignore[arg-type]
                    label=hit.symbol,
                    path=path.replace("\\", "/"),
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    route=route,
                    symbol=hit.symbol,
                    evidence_pack_id=pack_id,
                )
            )

            if node.node_type == "route":
                file_routes.append(node)
                pending_route = node
            elif node.node_type == "handler":
                file_handlers.append(node)
                if pending_route is not None:
                    add_edge(pending_route.id, node.id, "routes_to", f"{pending_route.label} -> {node.label}")
                    pending_route = None
            elif node.node_type == "auth_guard":
                file_auth.append(node)

        route_nodes_by_file[path] = file_routes
        handler_nodes_by_file[path] = file_handlers
        auth_nodes_by_file[path] = file_auth

        for hit in extract_symbols(lines, path):
            node = node_index.get(_node_id(path, hit.kind, hit.symbol, hit.line_start))
            if node is None:
                continue

            if node.node_type == "param_input":
                for handler in file_handlers:
                    if handler.line_start and node.line_start and abs(handler.line_start - node.line_start) <= 12:
                        add_edge(handler.id, node.id, "accepts_input", f"{handler.label} accepts {node.label}")

            if node.node_type in {"data_access", "storage_op", "ai_action", "config_secret"}:
                nearest_handler = _nearest_handler(file_handlers, node.line_start or 0)
                if nearest_handler:
                    add_edge(nearest_handler.id, node.id, "accesses", f"{nearest_handler.label} -> {node.label}")

            if node.node_type == "auth_guard" and hit.kind == "auth_guard":
                for handler in file_handlers:
                    if handler.line_start and node.line_start and abs(handler.line_start - node.line_start) <= 12:
                        add_edge(handler.id, node.id, "guarded_by", f"{handler.label} guarded by {node.label}")

        for handler in file_handlers:
            has_guard = any(
                edge.edge_type == "guarded_by" and edge.source_id == handler.id for edge in edges
            )
            if not has_guard and handler.route and not _PUBLIC_ROUTE.search(handler.route):
                if _SENSITIVE_ROUTE.search(handler.route) or _method_from_route_symbol(handler.label) != "GET":
                    missing = add_node(
                        AttackGraphNode(
                            id=_node_id(path, "missing_guard", handler.label, handler.line_start or 0),
                            node_type="auth_guard",
                            label="missing_auth_guard",
                            path=path.replace("\\", "/"),
                            line_start=handler.line_start,
                            line_end=handler.line_end,
                            route=handler.route,
                            symbol=handler.symbol,
                        )
                    )
                    add_edge(
                        handler.id,
                        missing.id,
                        "missing_guard",
                        f"{handler.label} lacks auth guard",
                    )

    _link_frontend_backend(nodes, edges, node_index, add_edge)
    _detect_ownership_gaps(project_root, nodes, edges, node_index, add_edge)
    _detect_ai_without_approval(project_root, nodes, edges, node_index, add_edge)

    return AttackGraph(nodes=nodes, edges=edges)


def _nearest_handler(handlers: list[AttackGraphNode], line: int) -> AttackGraphNode | None:
    candidates = [item for item in handlers if item.line_start and item.line_start <= line + 20]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.line_start or 0)


def _link_frontend_backend(
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
    node_index: dict[str, AttackGraphNode],
    add_edge,
) -> None:
    client_calls = [node for node in nodes if node.node_type == "client_call" and node.route]
    backend_routes = [node for node in nodes if node.node_type == "route"]

    for client in client_calls:
        route = client.route or ""
        for backend in backend_routes:
            backend_route = backend.route or ""
            if not backend_route or not route:
                continue
            if route.endswith(backend_route) or backend_route in route:
                add_edge(
                    client.id,
                    backend.id,
                    "frontend_trust",
                    f"frontend calls {backend_route}",
                )


def _detect_ownership_gaps(
    project_root: Path,
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
    node_index: dict[str, AttackGraphNode],
    add_edge,
) -> None:
    for node in nodes:
        if node.node_type != "param_input":
            continue
        param_label = node.label or ""
        if not _OWNER_PARAM.search(param_label):
            if node.path and node.line_start:
                lines = read_lines(project_root, node.path)
                if not lines:
                    continue
                line_text = lines[node.line_start - 1] if node.line_start <= len(lines) else ""
                if not _OWNER_PARAM.search(line_text):
                    continue
                param_label = line_text
            else:
                continue
        handler = _upstream_handler(node.id, edges, node_index)
        if handler is None:
            continue
        data_sinks = _downstream_nodes(handler.id, edges, node_index, {"data_access", "storage_op"})
        for sink in data_sinks:
            has_owner_check = any(
                edge.edge_type == "guarded_by"
                and edge.source_id == handler.id
                and "owner" in (node_index.get(edge.target_id).label if node_index.get(edge.target_id) else "")
                for edge in edges
            )
            if not has_owner_check:
                add_edge(
                    node.id,
                    sink.id,
                    "crosses_boundary",
                    f"{param_label.strip()} reaches {sink.label} without ownership check",
                )


def _detect_ai_without_approval(
    project_root: Path,
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
    node_index: dict[str, AttackGraphNode],
    add_edge,
) -> None:
    for node in nodes:
        if node.node_type != "ai_action":
            continue
        handler = _upstream_handler(node.id, edges, node_index)
        if handler is None:
            continue
        path = node.path or ""
        lines = read_lines(project_root, path)
        if not lines:
            continue
        block = "\n".join(lines[(node.line_start or 1) - 1 : (node.line_end or node.line_start or 1)])
        if not _APPROVAL.search(block):
            add_edge(
                handler.id,
                node.id,
                "crosses_boundary",
                f"{handler.label} invokes AI action without approval gate",
            )


def _upstream_handler(
    node_id: str,
    edges: list[AttackGraphEdge],
    node_index: dict[str, AttackGraphNode],
) -> AttackGraphNode | None:
    visited: set[str] = set()
    queue = [node_id]
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for edge in edges:
            if edge.target_id != current:
                continue
            source = node_index.get(edge.source_id)
            if source and source.node_type == "handler":
                return source
            queue.append(edge.source_id)
    return None


def _downstream_nodes(
    handler_id: str,
    edges: list[AttackGraphEdge],
    node_index: dict[str, AttackGraphNode],
    node_types: set[str],
) -> list[AttackGraphNode]:
    found: list[AttackGraphNode] = []
    for edge in edges:
        if edge.source_id != handler_id:
            continue
        target = node_index.get(edge.target_id)
        if target and target.node_type in node_types:
            found.append(target)
    return found
