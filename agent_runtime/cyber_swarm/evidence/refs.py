"""Evidence reference helpers."""

from __future__ import annotations

from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.models.agents import EvidenceRef


def evidence_from_pack(pack: EvidencePack, explanation: str) -> EvidenceRef:
    return EvidenceRef(
        type="file",
        path=pack.path,
        route=pack.route,
        line_start=pack.line_start,
        line_end=pack.line_end,
        snippet=pack.snippet,
        explanation=explanation,
        evidence_pack_id=pack.id,
        symbol=pack.symbol,
    )
