"""Tests for line-level evidence packs."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.agents.specialists.base import static_reproduction
from cyber_swarm.evidence.refs import evidence_from_pack
from cyber_swarm.evidence.extract import extract_python_symbols, extract_typescript_symbols
from cyber_swarm.evidence.ignore import should_ignore_scanned_path
from cyber_swarm.evidence.models import EvidencePack
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.evidence.reader import read_lines
from cyber_swarm.models.agents import AgentFindingDraft, EvidenceRef
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceAuth,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.verifier.verify import verify_draft


def _repo(tmp_path: Path, files: dict[str, str]) -> RepoIntelligence:
    inventory_files: list[FileInventoryItem] = []
    for rel_path, category in (
        ("backend/app/core/auth.py", "python"),
        ("backend/app/api/routes/me.py", "python"),
        ("src/hooks/useAuth.tsx", "typescript"),
        (".env", "config"),
        ("node_modules/ignored.py", "python"),
    ):
        if rel_path in files:
            inventory_files.append(FileInventoryItem(path=rel_path, category=category))

    return RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=len(inventory_files),
            by_category={"python": 2, "typescript": 1, "config": 1},
            files=inventory_files,
        ),
        surfaces=SurfacesResult(
            api=[SurfaceRoute(path="/api/me", file="backend/app/api/routes/me.py", framework="fastapi")],
            auth=[SurfaceAuth(file="backend/app/core/auth.py", type="bearer")],
        ),
    )


def test_extract_http_bearer_with_line_range(tmp_path: Path):
    auth_path = tmp_path / "backend" / "app" / "core"
    auth_path.mkdir(parents=True)
    lines = [
        "from fastapi.security import HTTPBearer",
        "",
        "_bearer_scheme = HTTPBearer(auto_error=False)",
        "",
        "async def get_current_user(token=Depends(_bearer_scheme)):",
        "    return token",
    ]
    (auth_path / "auth.py").write_text("\n".join(lines), encoding="utf-8")

    hits = extract_python_symbols(lines)
    bearer_hits = [hit for hit in hits if "HTTPBearer" in hit.symbol or "HTTPBearer" in lines[hit.line_start - 1]]
    assert bearer_hits
    bearer = next(hit for hit in hits if hit.line_start == 3)
    assert "HTTPBearer" in lines[bearer.line_start - 1]


def test_extract_fastapi_route_decorator_with_handler(tmp_path: Path):
    route_path = tmp_path / "backend" / "app" / "api" / "routes"
    route_path.mkdir(parents=True)
    lines = [
        "from fastapi import APIRouter",
        "router = APIRouter()",
        "",
        '@router.get("/api/me")',
        "async def read_me():",
        "    return {}",
    ]
    (route_path / "me.py").write_text("\n".join(lines), encoding="utf-8")

    hits = extract_python_symbols(lines)
    route_hit = next(hit for hit in hits if hit.kind == "route_decorator")
    assert route_hit.route == "/api/me"
    assert "GET" in route_hit.symbol


def test_extract_tsx_auth_hook(tmp_path: Path):
    hook_path = tmp_path / "src" / "hooks"
    hook_path.mkdir(parents=True)
    lines = [
        "import { createClient } from '@supabase/supabase-js'",
        "",
        "export const useAuth = () => {",
        "  const client = createClient(process.env.NEXT_PUBLIC_URL!, process.env.NEXT_PUBLIC_KEY!)",
        "  return client.auth",
        "}",
    ]
    (hook_path / "useAuth.tsx").write_text("\n".join(lines), encoding="utf-8")

    hits = extract_typescript_symbols(lines)
    assert any(hit.symbol == "useAuth" and hit.kind == "hook" for hit in hits)
    assert any(hit.symbol == "createClient" and hit.kind == "storage_client" for hit in hits)


def test_ignored_files_are_never_read(tmp_path: Path):
    ignored = tmp_path / "node_modules" / "pkg"
    ignored.mkdir(parents=True)
    (ignored / "secret.py").write_text("API_KEY=live\n", encoding="utf-8")

    assert should_ignore_scanned_path("node_modules/pkg/secret.py")
    assert read_lines(tmp_path, "node_modules/pkg/secret.py") is None


def test_build_evidence_packs_from_target_root(tmp_path: Path):
    auth_dir = tmp_path / "backend" / "app" / "core"
    auth_dir.mkdir(parents=True)
    (auth_dir / "auth.py").write_text(
        "_bearer_scheme = HTTPBearer(auto_error=False)\n",
        encoding="utf-8",
    )

    repo = _repo(tmp_path, {"backend/app/core/auth.py": "python"})
    packs = build_evidence_packs(tmp_path, repo, {"backend/app/core/auth.py"})
    assert packs
    assert any("HTTPBearer(auto_error=False)" in pack.snippet for pack in packs)
    assert all(pack.path == "backend/app/core/auth.py" for pack in packs if "HTTPBearer" in pack.snippet)


def test_weak_finding_without_pack_refs_is_rejected():
    draft = AgentFindingDraft(
        id="draft-weak",
        title="Missing auth guard on /api/login handler",
        vulnerability_class="broken-access-control",
        claim="The /api/login handler in src/auth.ts lacks requireAuth() enforcement before request processing.",
        affected_surfaces=["/api/login"],
        evidence=[
            EvidenceRef(
                type="file",
                path="src/auth.ts",
                line_start=12,
                line_end=28,
                snippet="export function requireAuth() {}",
                explanation="requireAuth() middleware in src/auth.ts is not invoked on the /api/login handler.",
            )
        ],
        impact_hypothesis="Unauthenticated requests can reach the login handler logic.",
        attack_path="Trace middleware registration for /api/login in src/auth.ts.",
        safe_reproduction=static_reproduction(
            ["Open src/auth.ts and trace middleware registration for /api/login."],
            "Guard invocation is absent on the login handler path.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=[],
        retrieval_trace=[],
    )
    scan_report = {
        "inventory": {"files": [{"path": "src/auth.ts", "category": "typescript"}]},
        "surfaces": {"api": [{"path": "/api/login", "file": "src/auth.ts"}], "routes": []},
    }
    result = verify_draft(draft, scan_report, context_paths={"src/auth.ts"}, evidence_packs=[])
    assert result.status == "rejected"
    assert result.rejected is not None
    assert any("evidence_pack_id" in check for check in result.rejected.failed_checks)


def test_strict_finding_with_pack_refs_can_verify():
    pack = EvidencePack(
        id="ep-001",
        path="src/auth.ts",
        line_start=12,
        line_end=28,
        snippet="export function requireAuth(req, res, next) { /* guard */ }",
        symbol="requireAuth",
        surface_type="auth",
        kind="function",
        route="/api/login",
    )
    draft = AgentFindingDraft(
        id="draft-auth-supported",
        title="Missing auth guard on /api/login handler",
        vulnerability_class="broken-access-control",
        claim=(
            "The /api/login handler in src/auth.ts lacks requireAuth() enforcement before "
            "request processing."
        ),
        affected_surfaces=["/api/login"],
        evidence=[
            evidence_from_pack(
                pack,
                "requireAuth() middleware in src/auth.ts is not invoked on the /api/login handler "
                "before request processing.",
            )
        ],
        impact_hypothesis="Unauthenticated requests can reach the login handler logic.",
        attack_path="Trace middleware registration for /api/login in src/auth.ts.",
        safe_reproduction=static_reproduction(
            ["Open src/auth.ts and trace middleware registration for /api/login."],
            "Guard invocation is absent on the login handler path.",
        ),
        confidence="medium",
        agent_type="auth",
        specialist="auth-breaker",
        selected_skills=["example-skill"],
        retrieval_trace=["c1"],
    )
    scan_report = {
        "inventory": {"files": [{"path": "src/auth.ts", "category": "typescript"}]},
        "surfaces": {"api": [{"path": "/api/login", "file": "src/auth.ts"}], "routes": []},
    }
    result = verify_draft(draft, scan_report, context_paths={"src/auth.ts"}, evidence_packs=[pack])
    assert result.status == "verified"
    assert result.verified is not None
    assert result.verified.affected_files == ["src/auth.ts"]
