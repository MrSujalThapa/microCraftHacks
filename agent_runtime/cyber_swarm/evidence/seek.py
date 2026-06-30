"""Evidence-seeking loop for specialist agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyber_swarm.evidence.extract import extract_symbols
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import classify_surface_type
from cyber_swarm.evidence.reader import excerpt_lines, read_lines
from cyber_swarm.models.attack_graph import AttackGraphNode

MAX_SEEK_ITERATIONS_DEMO = 2
MAX_SEEK_ITERATIONS_FULL = 3


@dataclass(frozen=True)
class EvidenceSeekRequest:
    kind: str
    path: str
    symbol: str | None = None
    line_hint: int | None = None
    reason: str = ""


def max_seek_iterations(*, demo: bool = False) -> int:
    return MAX_SEEK_ITERATIONS_DEMO if demo else MAX_SEEK_ITERATIONS_FULL


def seek_evidence_pack(
    project_root: Path,
    request: EvidenceSeekRequest,
    *,
    next_pack_id: str,
) -> EvidencePack | None:
    """Retrieve an additional evidence snippet for a specialist request."""
    rel_path = request.path.replace("\\", "/")
    file_path = project_root / rel_path
    if not file_path.is_file():
        return None

    try:
        lines = read_lines(project_root, rel_path)
    except OSError:
        return None
    if not lines:
        return None

    if request.kind == "handler_body" and request.symbol:
        for hit in extract_symbols(lines, rel_path):
            if hit.symbol == request.symbol and hit.kind in {"function", "route_handler"}:
                return EvidencePack(
                    id=next_pack_id,
                    path=rel_path,
                    line_start=hit.line_start,
                    line_end=min(hit.line_end + 12, len(lines)),
                    snippet=excerpt_lines(lines, hit.line_start, min(hit.line_end + 12, len(lines))),
                    symbol=hit.symbol,
                    surface_type=classify_surface_type(rel_path, hit.kind, hit.route),
                    kind=hit.kind,
                    route=hit.route,
                )

    if request.kind == "auth_helper":
        for hit in extract_symbols(lines, rel_path):
            if hit.kind in {"auth_guard", "dependency", "auth_helper", "auth_config"}:
                return EvidencePack(
                    id=next_pack_id,
                    path=rel_path,
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    snippet=excerpt_lines(lines, hit.line_start, hit.line_end),
                    symbol=hit.symbol,
                    surface_type="auth",
                    kind=hit.kind,
                    route=hit.route,
                )

    if request.kind == "storage_call":
        for hit in extract_symbols(lines, rel_path):
            if hit.kind in {"storage_op", "storage_client", "data_access"}:
                return EvidencePack(
                    id=next_pack_id,
                    path=rel_path,
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    snippet=excerpt_lines(lines, hit.line_start, hit.line_end),
                    symbol=hit.symbol,
                    surface_type="storage",
                    kind=hit.kind,
                    route=hit.route,
                )

    if request.kind == "frontend_caller":
        for hit in extract_symbols(lines, rel_path):
            if hit.kind in {"client_call", "hook", "function"}:
                return EvidencePack(
                    id=next_pack_id,
                    path=rel_path,
                    line_start=hit.line_start,
                    line_end=hit.line_end,
                    snippet=excerpt_lines(lines, hit.line_start, hit.line_end),
                    symbol=hit.symbol,
                    surface_type=classify_surface_type(rel_path, hit.kind, hit.route),
                    kind=hit.kind,
                    route=hit.route,
                )

    if request.line_hint:
        start = max(1, request.line_hint - 2)
        end = min(len(lines), request.line_hint + 10)
        return EvidencePack(
            id=next_pack_id,
            path=rel_path,
            line_start=start,
            line_end=end,
            snippet=excerpt_lines(lines, start, end),
            symbol=request.symbol,
            surface_type=classify_surface_type(rel_path, "function", None),
            kind="source",
        )

    return None


def seek_requests_for_nodes(nodes: list[AttackGraphNode]) -> list[EvidenceSeekRequest]:
    requests: list[EvidenceSeekRequest] = []
    for node in nodes:
        if not node.path:
            continue
        if node.node_type == "handler":
            requests.append(
                EvidenceSeekRequest(
                    kind="handler_body",
                    path=node.path,
                    symbol=node.symbol,
                    line_hint=node.line_start,
                    reason="Need handler body",
                )
            )
        elif node.node_type == "auth_guard":
            requests.append(
                EvidenceSeekRequest(
                    kind="auth_helper",
                    path=node.path,
                    symbol=node.symbol,
                    line_hint=node.line_start,
                    reason="Need auth helper definition",
                )
            )
        elif node.node_type in {"storage_op", "data_access"}:
            requests.append(
                EvidenceSeekRequest(
                    kind="storage_call",
                    path=node.path,
                    symbol=node.symbol,
                    line_hint=node.line_start,
                    reason="Need storage call site",
                )
            )
        elif node.node_type == "client_call":
            requests.append(
                EvidenceSeekRequest(
                    kind="frontend_caller",
                    path=node.path,
                    symbol=node.symbol,
                    line_hint=node.line_start,
                    reason="Need frontend caller",
                )
            )
    return requests
