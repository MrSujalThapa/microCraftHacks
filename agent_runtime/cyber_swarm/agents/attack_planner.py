"""Deterministic attack planner agent."""

from __future__ import annotations

from cyber_swarm.models.agents import AttackHypothesis, ReconReport
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput

SPECIALIST_BY_TARGET = {
    "auth": "auth-boundary",
    "api": "api-abuse",
    "secrets": "secrets-config",
    "dependency": "secrets-config",
    "storage": "storage-access",
    "ai": "ai-action-boundary",
    "config": "secrets-config",
}


def _skills_for_target(runtime_input: RuntimeInput, agent_type: str) -> list[str]:
    return [
        skill.name
        for skill in runtime_input.routed_skills.selected
        if agent_type in skill.agent_types
    ][:3]


def run_attack_planner(
    runtime_input: RuntimeInput,
    recon: ReconReport,
    selected_context: list[RetrievedContext],
) -> list[AttackHypothesis]:
    hypotheses: list[AttackHypothesis] = []
    context_paths = {
        item.source_path for item in selected_context if item.source_path and item.context_category != "test"
    }

    if "auth" in recon.selected_agent_targets:
        auth_files = []
        auth_routes = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "auth":
                auth_files.extend(boundary.files)
                auth_routes.extend(boundary.routes)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-auth-1",
                agent_type="auth",
                specialist="auth-boundary",
                title="Auth boundary bypass or missing enforcement",
                vulnerability_class="broken-access-control",
                target_surfaces=auth_routes[:6] or ["/api/login"],
                target_files=sorted(set(auth_files) & context_paths) or auth_files[:4],
                reasoning="Auth boundary files and login routes were mapped during recon.",
                required_evidence=[
                    "auth middleware or guard implementation",
                    "route-to-handler mapping for protected endpoints",
                ],
                priority="high",
            )
        )
        hypotheses.append(
            AttackHypothesis(
                id="hyp-ownership-1",
                agent_type="auth",
                specialist="object-ownership",
                title="Missing object ownership check (BOLA/IDOR)",
                vulnerability_class="bola",
                target_surfaces=auth_routes[:6],
                target_files=sorted(set(auth_files) & context_paths) or auth_files[:4],
                reasoning="Auth boundary files may accept user-controlled IDs without ownership validation.",
                required_evidence=[
                    "handler accepting user/resource identifier",
                    "data access call without ownership check",
                ],
                priority="high",
            )
        )

    if "api" in recon.selected_agent_targets:
        api_routes = []
        api_files = []
        for surface in recon.high_risk_surfaces:
            if surface.surface_type == "api":
                api_routes.append(surface.path)
                api_files.append(surface.file)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-api-1",
                agent_type="api",
                specialist="api-abuse",
                title="API handler abuse or missing schema validation",
                vulnerability_class="api-abuse",
                target_surfaces=sorted(set(api_routes))[:8],
                target_files=sorted(set(api_files) & context_paths) or sorted(set(api_files))[:4],
                reasoning="High-risk API routes were identified from repo surfaces and retrieval context.",
                required_evidence=[
                    "API route handler source",
                    "input validation or schema enforcement",
                ],
                priority="high" if api_routes else "medium",
            )
        )

    if "secrets" in recon.selected_agent_targets:
        config_files = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "secrets-config":
                config_files.extend(boundary.files)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-secrets-1",
                agent_type="secrets",
                specialist="secrets-config",
                title="Secrets or credentials exposed in config",
                vulnerability_class="secret-exposure",
                target_surfaces=[],
                target_files=sorted(set(config_files) & context_paths) or config_files[:4],
                reasoning="Configuration and environment files were mapped as secret boundaries.",
                required_evidence=[
                    "config file containing credential-like keys",
                    "redacted secret pattern in repository config",
                ],
                priority="high" if config_files else "medium",
            )
        )

    if "dependency" in recon.selected_agent_targets:
        dependency_files = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "dependency":
                dependency_files.extend(boundary.files)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-dependency-1",
                agent_type="dependency",
                specialist="secrets-config",
                title="Dependency or supply-chain misconfiguration",
                vulnerability_class="security-misconfiguration",
                target_surfaces=[],
                target_files=sorted(set(dependency_files) & context_paths) or dependency_files[:4],
                reasoning="Dependency manifests were mapped during recon.",
                required_evidence=[
                    "package manifest with risky dependency patterns",
                    "lockfile or dependency configuration",
                ],
                priority="medium",
            )
        )

    if "storage" in recon.selected_agent_targets:
        storage_routes = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "storage":
                storage_routes.extend(boundary.routes)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-storage-1",
                agent_type="storage",
                specialist="storage-access",
                title="Storage or upload endpoint abuse",
                vulnerability_class="privilege-escalation",
                target_surfaces=storage_routes[:8],
                target_files=sorted(context_paths)[:3],
                reasoning="Storage-related routes or stack signals were mapped during recon.",
                required_evidence=[
                    "storage/upload route handler",
                    "access control around object storage",
                ],
                priority="medium",
            )
        )

    if "ai" in recon.selected_agent_targets:
        ai_files = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "ai":
                ai_files.extend(boundary.files)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-ai-1",
                agent_type="ai",
                specialist="ai-action-boundary",
                title="AI integration action without approval gate",
                vulnerability_class="ai-action-abuse",
                target_surfaces=[],
                target_files=sorted(set(ai_files) & context_paths) or ai_files[:4],
                reasoning="AI/LLM integration signals were mapped during recon.",
                required_evidence=[
                    "AI provider configuration",
                    "prompt or model integration source",
                ],
                priority="medium",
            )
        )

    if "config" in recon.selected_agent_targets and not any(h.agent_type == "secrets" for h in hypotheses):
        config_files = []
        for boundary in recon.trust_boundaries:
            if boundary.boundary_type == "secrets-config":
                config_files.extend(boundary.files)
        hypotheses.append(
            AttackHypothesis(
                id="hyp-config-1",
                agent_type="config",
                specialist="secrets-config",
                title="Configuration hardening review",
                vulnerability_class="security-misconfiguration",
                target_surfaces=[],
                target_files=sorted(set(config_files) & context_paths) or config_files[:4],
                reasoning="Config-only repo mapped for configuration review.",
                required_evidence=["project configuration files"],
                priority="medium",
            )
        )

    for target in recon.selected_agent_targets:
        if target in SPECIALIST_BY_TARGET and not any(h.agent_type == target for h in hypotheses):
            hypotheses.append(
                AttackHypothesis(
                    id=f"hyp-{target}-fallback",
                    agent_type=target,
                    specialist=SPECIALIST_BY_TARGET[target],
                    title=f"Investigate {target} boundary",
                    vulnerability_class="security-misconfiguration",
                    target_surfaces=[],
                    target_files=sorted(context_paths)[:3],
                    reasoning="Fallback hypothesis generated from selected agent target.",
                    required_evidence=["supporting production source context"],
                    priority="low",
                )
            )

    _ = _skills_for_target
    return hypotheses
