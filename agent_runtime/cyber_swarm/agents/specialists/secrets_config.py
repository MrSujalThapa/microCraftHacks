"""Secrets and config specialist agent."""

from __future__ import annotations

from cyber_swarm.agents.specialists.base import (
    context_for_paths,
    evidence_from_context,
    file_contains_secret_pattern,
    production_context,
    skills_for_agent,
    static_reproduction,
)
from cyber_swarm.models.agents import AgentFindingDraft, AttackHypothesis
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput


def run_secrets_config(
    hypothesis: AttackHypothesis,
    runtime_input: RuntimeInput,
    selected_context: list[RetrievedContext],
) -> AgentFindingDraft | None:
    relevant = context_for_paths(selected_context, hypothesis.target_files)
    config_context = [
        item
        for item in production_context(selected_context)
        if item.context_category in {"config", "auth", "source"}
        and (
            (item.source_path and any(token in item.source_path.lower() for token in (".env", "config", "secret")))
            or file_contains_secret_pattern(item.source_path or "", item.excerpt)
        )
    ]
    evidence_items = [item for item in (relevant or config_context) if item.source_path]
    if not evidence_items:
        return None

    strong_items = [
        item
        for item in evidence_items
        if file_contains_secret_pattern(item.source_path or "", item.excerpt)
        or (item.source_path and ".env" in item.source_path.lower())
    ]
    if not strong_items:
        return None

    evidence = [
        evidence_from_context(item, "Configuration excerpt contains credential-like patterns (redacted)")
        for item in strong_items[:3]
    ]

    return AgentFindingDraft(
        id="draft-secrets-1",
        title="Potential secret exposure in configuration",
        vulnerability_class=hypothesis.vulnerability_class,
        claim=(
            "Static configuration evidence includes credential-like keys or environment files that "
            "should not contain live secrets in the repository."
        ),
        affected_surfaces=[item.source_path for item in strong_items if item.source_path][:4],
        evidence=evidence,
        impact_hypothesis="Exposed secrets in config files can enable credential theft or lateral movement.",
        attack_path="Inspect config/env files for hardcoded secrets and rotate any exposed values.",
        safe_reproduction=static_reproduction(
            [
                "Review identified config files for credential-like keys.",
                "Confirm secrets are redacted in reports and not echoed in logs.",
            ],
            "Document credential-like patterns in config without exfiltrating values.",
        ),
        confidence="high" if len(strong_items) > 1 else "medium",
        agent_type="secrets",
        specialist="secrets-config",
        selected_skills=skills_for_agent(runtime_input, "secrets"),
        retrieval_trace=[item.id for item in strong_items],
    )
