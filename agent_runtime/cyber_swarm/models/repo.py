"""Typed models for repo intelligence from TypeScript scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FileInventoryItem:
    path: str
    category: str


@dataclass(frozen=True)
class InventoryResult:
    total_files: int
    by_category: dict[str, int]
    files: list[FileInventoryItem]


@dataclass(frozen=True)
class StackDetection:
    name: str
    confidence: str
    evidence: list[str]


@dataclass(frozen=True)
class SurfaceRoute:
    path: str
    file: str
    framework: str | None = None


@dataclass(frozen=True)
class SurfaceAuth:
    file: str
    type: str | None = None


@dataclass(frozen=True)
class SurfaceDataModel:
    file: str
    name: str | None = None


@dataclass(frozen=True)
class SurfacesResult:
    routes: list[SurfaceRoute] = field(default_factory=list)
    api: list[SurfaceRoute] = field(default_factory=list)
    auth: list[SurfaceAuth] = field(default_factory=list)
    data_models: list[SurfaceDataModel] = field(default_factory=list)


@dataclass(frozen=True)
class RepoIntelligence:
    version: str
    scanned_at: str
    project_root: str
    inventory: InventoryResult
    stack: list[StackDetection] = field(default_factory=list)
    surfaces: SurfacesResult = field(default_factory=SurfacesResult)

    @property
    def scan_id(self) -> str:
        return self.scanned_at.replace(":", "-").replace(".", "-")
