"""Tests for deterministic secret draft generation."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.evidence.draft_helpers import build_deterministic_secret_drafts
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfacesResult,
)
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.redaction import redact_secrets


def _runtime_input(tmp_path: Path) -> RuntimeInput:
    (tmp_path / "backend").mkdir(parents=True)
    (tmp_path / "backend" / ".env").write_text(
        "SUPABASE_SERVICE_ROLE_KEY=super-secret-service-role\n",
        encoding="utf-8",
    )

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=1,
            by_category={"config": 1},
            files=[FileInventoryItem(path="backend/.env", category="config")],
        ),
        surfaces=SurfacesResult(),
    )
    return RuntimeInput(
        scan_report_path=tmp_path / "scan.json",
        routed_skills_path=tmp_path / "routed.json",
        repo=repo,
        routed_skills=RoutedSkills(
            report_path=str(tmp_path / "scan.json"),
            routed_at="2026-06-29T12:01:00.000Z",
            selected=[
                SelectedSkill(
                    name="secrets-config",
                    path="skills/example/SKILL.md",
                    score=0.9,
                    reasons=["config"],
                    agent_types=["secrets"],
                )
            ],
        ),
    )


def test_build_deterministic_secret_drafts_from_env_key_pack(tmp_path: Path):
    runtime_input = _runtime_input(tmp_path)
    packs = build_evidence_packs(tmp_path, runtime_input.repo, {"backend/.env"})

    drafts = build_deterministic_secret_drafts(runtime_input, packs, [])

    assert len(drafts) >= 1
    draft = drafts[0]
    assert draft.vulnerability_class == "secret-exposure"
    assert draft.specialist == "secrets-config"
    assert draft.affected_surfaces == []
    assert draft.evidence[0].path == "backend/.env"
    assert "SUPABASE_SERVICE_ROLE_KEY" in draft.title
    assert draft.evidence[0].line_start is not None
    assert "super-secret-service-role" not in redact_secrets(draft.evidence[0].snippet or "")
