"""Tests for env/config evidence pack ingestion."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.evidence.draft_helpers import build_deterministic_secret_drafts
from cyber_swarm.evidence.env_config import is_env_config_path
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.evidence.secret_packs import is_secret_evidence_pack
from cyber_swarm.graph.evidence_nodes import build_evidence_packs_node
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceAuth,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.runtime_config import RuntimeConfig
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.rag.redaction import contains_raw_secret

RAW_SECRET = "SUPABASE_SERVICE_ROLE_KEY=fake_test_value_not_a_real_secret"


def _runtime_input(tmp_path: Path, repo: RepoIntelligence) -> RuntimeInput:
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


def test_is_env_config_path_matches_nested_dotfiles():
    assert is_env_config_path(".env")
    assert is_env_config_path(".env.local")
    assert is_env_config_path("backend/.env")
    assert is_env_config_path("frontend/.env")
    assert is_env_config_path("config/prod.env")
    assert not is_env_config_path("node_modules/pkg/.env")


def test_backend_env_creates_redacted_evidence_pack(tmp_path: Path):
    (tmp_path / "backend").mkdir(parents=True)
    (tmp_path / "backend" / ".env").write_text(
        f"SUPABASE_SERVICE_ROLE_KEY={RAW_SECRET}\n",
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

    packs = build_evidence_packs(tmp_path, repo, set(), max_packs=12)
    secret_packs = [pack for pack in packs if pack.path == "backend/.env"]

    assert secret_packs
    service_role = next(pack for pack in secret_packs if pack.symbol == "SUPABASE_SERVICE_ROLE_KEY")
    assert service_role.kind == "env_key"
    assert service_role.surface_type == "config"
    assert "SUPABASE_SERVICE_ROLE_KEY=<REDACTED_SECRET>" in service_role.snippet
    assert RAW_SECRET not in service_role.snippet
    assert not contains_raw_secret(service_role.snippet)


def test_deterministic_secret_draft_from_env_pack(tmp_path: Path):
    (tmp_path / "backend").mkdir(parents=True)
    (tmp_path / "backend" / ".env").write_text(
        f"SUPABASE_SERVICE_ROLE_KEY={RAW_SECRET}\n",
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
    runtime_input = _runtime_input(tmp_path, repo)
    packs = build_evidence_packs(tmp_path, repo, set(), max_packs=12)
    drafts = build_deterministic_secret_drafts(runtime_input, packs, [])

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.vulnerability_class == "secret-exposure"
    assert draft.evidence[0].path == "backend/.env"
    assert RAW_SECRET not in draft.claim
    assert RAW_SECRET not in (draft.evidence[0].snippet or "")


def test_env_example_placeholder_skips_secret_pack(tmp_path: Path):
    (tmp_path / "backend").mkdir(parents=True)
    (tmp_path / "backend" / ".env.example").write_text(
        "SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here\n",
        encoding="utf-8",
    )

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=1,
            by_category={"config": 1},
            files=[FileInventoryItem(path="backend/.env.example", category="config")],
        ),
        surfaces=SurfacesResult(),
    )

    packs = build_evidence_packs(tmp_path, repo, set(), max_packs=12)
    assert not any(pack.symbol == "SUPABASE_SERVICE_ROLE_KEY" for pack in packs)


def test_demo_mode_keeps_env_secret_when_api_route_packs_exist(tmp_path: Path):
    backend = tmp_path / "backend" / "app"
    backend.mkdir(parents=True)
    (tmp_path / "backend" / ".env").write_text(
        f"SUPABASE_SERVICE_ROLE_KEY={RAW_SECRET}\n",
        encoding="utf-8",
    )
    route_lines = "\n".join(
        [
            "from fastapi import APIRouter",
            "router = APIRouter()",
            "",
        ]
        + [f'@router.get("/api/route{i}")\ndef handler_{i}(): return {{}}' for i in range(20)]
    )
    (backend / "main.py").write_text(route_lines, encoding="utf-8")

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=2,
            by_category={"config": 1, "python": 1},
            files=[
                FileInventoryItem(path="backend/.env", category="config"),
                FileInventoryItem(path="backend/app/main.py", category="python"),
            ],
        ),
        surfaces=SurfacesResult(
            api=[SurfaceRoute(path=f"/api/route{i}", file="backend/app/main.py", framework="fastapi") for i in range(20)]
        ),
    )

    runtime_input = _runtime_input(tmp_path, repo)
    state = {
        "runtime_input": runtime_input,
        "runtime_config": RuntimeConfig(mode="demo"),
        "selected_context": [],
        "metrics": {},
    }
    updated = build_evidence_packs_node(state)
    packs = updated["evidence_packs"]

    assert any(
        pack.path == "backend/.env" and pack.symbol == "SUPABASE_SERVICE_ROLE_KEY" for pack in packs
    )
    assert any(is_secret_evidence_pack(pack) for pack in packs)
    assert all(RAW_SECRET not in pack.snippet for pack in packs)
