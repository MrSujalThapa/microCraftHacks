"""Evidence pack models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

SurfaceType = Literal["auth", "api", "storage", "ai", "config", "dependency", "source"]


@dataclass(frozen=True)
class EvidencePack:
    id: str
    path: str
    line_start: int
    line_end: int
    snippet: str
    symbol: str | None
    surface_type: SurfaceType
    kind: str
    route: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
