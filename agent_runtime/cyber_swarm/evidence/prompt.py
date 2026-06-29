"""Format evidence packs for specialist prompts."""

from __future__ import annotations

from cyber_swarm.evidence.models import EvidencePack


def format_packs_for_prompt(packs: list[EvidencePack], *, limit: int = 24) -> str:
    lines: list[str] = []
    for pack in packs[:limit]:
        symbol = f" symbol={pack.symbol}" if pack.symbol else ""
        route = f" route={pack.route}" if pack.route else ""
        lines.append(
            f"- {pack.id} [{pack.surface_type}] {pack.path}:{pack.line_start}-{pack.line_end}"
            f"{symbol}{route}"
        )
    return "\n".join(lines)
