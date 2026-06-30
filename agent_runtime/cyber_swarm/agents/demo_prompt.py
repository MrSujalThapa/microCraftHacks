"""Compact demo-mode prompt builder for focused LLM reasoning."""

from __future__ import annotations

from typing import Any

from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.secret_packs import is_secret_evidence_pack
from cyber_swarm.models.agents import AgentFindingDraft
from cyber_swarm.models.attack_graph import AttackGraph, AttackGraphEdge, AttackGraphNode
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.rag.redaction import redact_secrets
from cyber_swarm.verifier.demo_quality import is_public_route

DEMO_PROMPT_VERSION = "demo-confirm-v2"

_LATENCY_CAPS: dict[str, dict[str, int]] = {
    "fastest": {
        "max_packs": 3,
        "max_paths": 1,
        "max_playbooks": 1,
        "max_findings": 1,
        "snippet_chars": 60,
        "max_output_tokens": 450,
    },
    "balanced": {
        "max_packs": 3,
        "max_paths": 2,
        "max_playbooks": 2,
        "max_findings": 1,
        "snippet_chars": 80,
        "max_output_tokens": 700,
    },
    "thorough": {
        "max_packs": 5,
        "max_paths": 3,
        "max_playbooks": 3,
        "max_findings": 2,
        "snippet_chars": 100,
        "max_output_tokens": 1000,
    },
}

_PUBLIC_ROUTES = frozenset({"/", "/health", "/api/health", "/status", "/ping"})


def latency_caps(runtime_config: RuntimeConfig) -> dict[str, int]:
    return dict(_LATENCY_CAPS[runtime_config.effective_latency])


def effective_max_confirmations(
    runtime_config: RuntimeConfig,
    candidates: list[AgentFindingDraft],
) -> int:
    caps = latency_caps(runtime_config)
    max_findings = caps["max_findings"]
    if runtime_config.effective_latency != "balanced":
        return max_findings

    high_signal = [
        draft
        for draft in candidates
        if draft.confidence == "high"
        and draft.vulnerability_class in {"secret-exposure", "bola", "privilege-escalation"}
    ]
    distinct = {draft.vulnerability_class for draft in high_signal}
    if len(distinct) >= 2 and len(high_signal) >= 2:
        return min(2, caps.get("max_findings_thorough_cap", 2))
    return 1


def _pack_priority(pack: EvidencePack) -> tuple[int, str]:
    if is_secret_evidence_pack(pack):
        return (0, pack.id)
    if pack.surface_type in {"config", "auth", "dependency"}:
        return (1, pack.id)
    if pack.route and is_public_route(pack.route):
        return (99, pack.id)
    return (2, pack.id)


def select_top_evidence_packs(
    packs: list[EvidencePack],
    *,
    max_packs: int,
) -> list[EvidencePack]:
    filtered = [
        pack
        for pack in packs
        if not (pack.route and is_public_route(pack.route))
    ]
    ranked = sorted(filtered, key=_pack_priority)
    selected: list[EvidencePack] = []
    seen_paths: set[str] = set()
    for pack in ranked:
        path_key = f"{pack.path}:{pack.line_start}"
        if path_key in seen_paths and not is_secret_evidence_pack(pack):
            continue
        seen_paths.add(path_key)
        selected.append(pack)
        if len(selected) >= max_packs:
            break
    return selected


def _path_priority(edge: AttackGraphEdge, graph: AttackGraph) -> tuple[int, str]:
    if edge.edge_type == "missing_guard":
        handler = graph.node_by_id(edge.source_id)
        if handler and handler.route and handler.route.strip().lower() in _PUBLIC_ROUTES:
            return (99, edge.id)
        return (0, edge.id)
    if edge.edge_type == "crosses_boundary":
        label = edge.label.lower()
        if "ownership" in label or "service" in label or "ai action" in label:
            return (1, edge.id)
        return (2, edge.id)
    source = graph.node_by_id(edge.source_id)
    if source and source.node_type == "config_secret":
        return (0, edge.id)
    return (5, edge.id)


def _format_graph_path(
    graph: AttackGraph,
    edge: AttackGraphEdge,
) -> dict[str, Any] | None:
    source = graph.node_by_id(edge.source_id)
    sink = graph.node_by_id(edge.target_id)
    if source is None or sink is None:
        return None
    if source.route and source.route.strip().lower() in _PUBLIC_ROUTES:
        return None
    if sink.route and sink.route.strip().lower() in _PUBLIC_ROUTES:
        return None
    return {
        "pathId": edge.id,
        "edgeType": edge.edge_type,
        "label": edge.label[:80],
        "sourcePackId": source.evidence_pack_id,
        "sinkPackId": sink.evidence_pack_id,
    }


def select_top_graph_paths(
    graph: AttackGraph | None,
    *,
    max_paths: int,
) -> list[dict[str, Any]]:
    if graph is None:
        return []

    candidates: list[tuple[tuple[int, str], dict[str, Any]]] = []
    for edge in graph.edges:
        if edge.edge_type not in {
            "missing_guard",
            "crosses_boundary",
            "frontend_trust",
            "accepts_input",
        }:
            continue
        formatted = _format_graph_path(graph, edge)
        if formatted is None:
            continue
        candidates.append((_path_priority(edge, graph), formatted))

    candidates.sort(key=lambda item: item[0])
    return [item[1] for item in candidates[:max_paths]]


def build_playbook_cards(
    routed_skills: dict[str, Any],
    *,
    max_playbooks: int,
) -> list[dict[str, Any]]:
    selected = routed_skills.get("selected", [])
    if not isinstance(selected, list):
        return []

    cards: list[dict[str, Any]] = []
    for skill in selected[:max_playbooks]:
        if not isinstance(skill, dict):
            continue
        reasons = skill.get("reasons", [])
        reason_list = [str(item) for item in reasons if isinstance(item, str)]
        cards.append(
            {
                "name": str(skill.get("name", "unknown")),
                "whyRouted": (reason_list[0] if reason_list else "matched repo signals")[:100],
                "checklist": reason_list[:3],
            }
        )
    return cards


def compact_pack_for_prompt(pack: EvidencePack, *, snippet_chars: int) -> dict[str, Any]:
    snippet = redact_secrets(pack.snippet).replace("\n", " ").strip()
    if len(snippet) > snippet_chars:
        snippet = snippet[: snippet_chars - 3] + "..."
    payload: dict[str, Any] = {
        "id": pack.id,
        "surfaceType": pack.surface_type,
        "path": pack.path,
        "lines": f"{pack.line_start}-{pack.line_end}",
        "snippet": snippet,
    }
    if pack.symbol:
        payload["symbol"] = pack.symbol
    return payload


def compact_candidate_for_prompt(draft: AgentFindingDraft) -> dict[str, Any]:
    evidence_cards = []
    for item in draft.evidence:
        if not item.evidence_pack_id:
            continue
        evidence_cards.append(
            {
                "evidencePackId": item.evidence_pack_id,
                "path": item.path,
                "lineStart": item.line_start,
                "lineEnd": item.line_end,
                "snippet": redact_secrets(item.snippet or "")[:80],
            }
        )
    return {
        "candidateId": draft.id,
        "category": draft.vulnerability_class,
        "specialist": draft.specialist,
        "title": redact_secrets(draft.title)[:120],
        "evidencePackIds": [card["evidencePackId"] for card in evidence_cards],
        "evidence": evidence_cards,
    }


def build_demo_llm_payload(
    *,
    evidence_packs: list[EvidencePack],
    attack_graph: AttackGraph | None,
    routed_skills: dict[str, Any],
    deterministic_candidates: list[AgentFindingDraft],
    runtime_config: RuntimeConfig,
) -> dict[str, Any]:
    caps = latency_caps(runtime_config)
    non_generic_candidates = [
        draft
        for draft in deterministic_candidates
        if not _is_generic_route_validation_candidate(draft)
    ]
    max_confirmations = effective_max_confirmations(runtime_config, non_generic_candidates)

    return {
        "task": "confirm_candidates",
        "promptVersion": DEMO_PROMPT_VERSION,
        "latencyMode": runtime_config.effective_latency,
        "maxConfirmations": max_confirmations,
        "evidencePacks": [
            compact_pack_for_prompt(pack, snippet_chars=caps["snippet_chars"])
            for pack in select_top_evidence_packs(evidence_packs, max_packs=caps["max_packs"])
        ],
        "graphPaths": select_top_graph_paths(attack_graph, max_paths=caps["max_paths"]),
        "playbookCards": build_playbook_cards(routed_skills, max_playbooks=caps["max_playbooks"]),
        "deterministicCandidates": [
            compact_candidate_for_prompt(draft)
            for draft in non_generic_candidates[: max_confirmations + 2]
        ],
        "responseSchema": {
            "confirmations": [
                {
                    "candidateId": "string",
                    "confirmed": "boolean",
                    "why_qa_misses_this": "string",
                    "why_code_review_misses_this": "string",
                    "suggested_regression_test": "string",
                    "recommended_fix": "string",
                }
            ],
            "reject_all": "boolean",
        },
        "rules": [
            "JSON only. No markdown. No prose outside JSON.",
            "Confirm or reject existing deterministicCandidates only; do not invent new locations.",
            "Set confirmed=true only when candidate evidencePackIds are sufficient.",
            "Do not change paths, lines, snippets, or evidencePackIds.",
            "Each string field: one sentence max.",
            f"Return at most {max_confirmations} confirmed candidates or reject_all=true.",
            "Reject generic route-validation and public health endpoint noise.",
        ],
    }


def _is_generic_route_validation_candidate(draft: AgentFindingDraft) -> bool:
    title_lower = draft.title.lower()
    if "lacks visible validation" in title_lower and draft.specialist == "api-abuse":
        return True
    if "lacks visible auth dependency" in title_lower:
        for surface in draft.affected_surfaces:
            if surface.strip().lower() in _PUBLIC_ROUTES:
                return True
    return False
