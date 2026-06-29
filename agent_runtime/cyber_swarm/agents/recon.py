"""Deterministic recon agent."""

from __future__ import annotations

from cyber_swarm.models.agents import HighRiskSurface, ReconReport, TrustBoundary
from cyber_swarm.models.repo import RepoIntelligence
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.rag.categories import is_test_path


def _production_context(context: list[RetrievedContext]) -> list[RetrievedContext]:
    return [item for item in context if item.context_category != "test" or not item.is_supporting]


def run_recon(runtime_input: RuntimeInput, selected_context: list[RetrievedContext]) -> ReconReport:
    repo = runtime_input.repo
    context = _production_context(selected_context)
    trust_boundaries: list[TrustBoundary] = []
    high_risk: list[HighRiskSurface] = []
    targets: set[str] = set()

    auth_files = [auth.file for auth in repo.surfaces.auth if not is_test_path(auth.file)]
    if auth_files:
        trust_boundaries.append(
            TrustBoundary(
                boundary_type="auth",
                description="Authentication and session enforcement boundary",
                files=auth_files,
                routes=[route.path for route in repo.surfaces.api if "login" in route.path.lower()],
            )
        )
        targets.add("auth")

    api_routes = [*repo.surfaces.api, *repo.surfaces.routes]
    if api_routes:
        route_files = sorted({route.file for route in api_routes if not is_test_path(route.file)})
        trust_boundaries.append(
            TrustBoundary(
                boundary_type="api",
                description="HTTP route handlers and external request boundary",
                files=route_files,
                routes=[route.path for route in api_routes],
            )
        )
        targets.add("api")

    config_files = [
        item.path
        for item in repo.inventory.files
        if item.category in {"config", "json", "yaml"}
        and not is_test_path(item.path)
        and any(token in item.path.lower() for token in (".env", "config", "secret", "settings"))
    ]
    if config_files:
        trust_boundaries.append(
            TrustBoundary(
                boundary_type="secrets-config",
                description="Environment and configuration secret boundary",
                files=config_files[:8],
            )
        )
        targets.add("secrets")

    if repo.surfaces.data_models:
        model_files = [model.file for model in repo.surfaces.data_models if not is_test_path(model.file)]
        trust_boundaries.append(
            TrustBoundary(
                boundary_type="data-ownership",
                description="Persistent data model and ownership boundary",
                files=model_files,
            )
        )

    for route in api_routes:
        if is_test_path(route.file):
            continue
        lowered = route.path.lower()
        if any(token in lowered for token in ("login", "auth", "admin", "upload", "order")):
            high_risk.append(
                HighRiskSurface(
                    surface_type="api",
                    path=route.path,
                    file=route.file,
                    reason="Route name indicates auth, admin, or sensitive workflow handling",
                )
            )

    for item in context:
        if item.context_category == "auth" and item.source_path:
            high_risk.append(
                HighRiskSurface(
                    surface_type="auth",
                    path=item.source_path,
                    file=item.source_path,
                    reason="Retrieved auth-related production context",
                )
            )

    for item in context:
        if item.context_category == "config" and item.source_path:
            high_risk.append(
                HighRiskSurface(
                    surface_type="config",
                    path=item.source_path,
                    file=item.source_path,
                    reason="Configuration file may contain credentials or trust settings",
                )
            )
            targets.add("secrets")

    if not targets:
        targets.update({"recon", "api"})

    deduped_risk: dict[tuple[str, str], HighRiskSurface] = {}
    for surface in high_risk:
        deduped_risk[(surface.surface_type, surface.path)] = surface

    return ReconReport(
        trust_boundaries=trust_boundaries,
        high_risk_surfaces=list(deduped_risk.values())[:12],
        selected_agent_targets=sorted(targets),
    )
