"""Tests for attack graph and cross-file specialist reasoning."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.agents.specialists.runner import run_specialists
from cyber_swarm.evidence.packs import build_evidence_packs
from cyber_swarm.graph.attack_graph_builder import build_attack_graph
from cyber_swarm.models.agents import AttackHypothesis
from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.models.retrieval import RetrievedContext
from cyber_swarm.models.runtime import RuntimeInput
from cyber_swarm.models.skills import RoutedSkills, SelectedSkill
from cyber_swarm.verifier.verify import verify_draft


def _repo(tmp_path: Path, files: dict[str, str], routes: list[SurfaceRoute]) -> RepoIntelligence:
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    return RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=len(files),
            by_category={"python": len(files)},
            files=[FileInventoryItem(path=path, category="python") for path in files],
        ),
        surfaces=SurfacesResult(api=routes),
    )


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
                    name="testing-api-security-with-owasp-top-10",
                    path="skills/example/SKILL.md",
                    score=0.8,
                    reasons=["matched keyword: api"],
                    agent_types=["api", "auth", "secrets", "storage", "ai"],
                )
            ],
        ),
    )


def _scan_report(repo: RepoIntelligence) -> dict:
    return {
        "inventory": {
            "files": [{"path": item.path, "category": item.category} for item in repo.inventory.files]
        },
        "surfaces": {
            "api": [{"path": route.path, "file": route.file} for route in repo.surfaces.api],
        },
    }


def _build_graph_and_packs(tmp_path: Path, repo: RepoIntelligence):
    paths = {item.path for item in repo.inventory.files}
    packs = build_evidence_packs(tmp_path, repo, paths)
    pack_lookup = {(pack.path, pack.line_start): pack.id for pack in packs}
    graph = build_attack_graph(tmp_path, repo, paths, pack_id_by_location=pack_lookup)
    return graph, packs


def test_attack_graph_includes_route_handler_edges(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.get('/api/documents/{document_id}')\n"
                "async def get_document(document_id: str = Path(...)):\n"
                "    return db.session.query(Document).filter_by(id=document_id).first()\n"
            ),
        },
        [SurfaceRoute(path="/api/documents/{document_id}", file="backend/app/main.py", framework="fastapi")],
    )
    graph, _ = _build_graph_and_packs(tmp_path, repo)

    route_nodes = [node for node in graph.nodes if node.node_type == "route"]
    handler_nodes = [node for node in graph.nodes if node.node_type == "handler"]
    assert route_nodes
    assert handler_nodes
    assert any(edge.edge_type == "routes_to" for edge in graph.edges)


def test_missing_ownership_check_detected(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.get('/api/documents/{document_id}')\n"
                "async def get_document(document_id: str = Path(...), user=Depends(get_current_user)):\n"
                "    return db.session.query(Document).filter_by(id=document_id).first()\n"
            ),
        },
        [SurfaceRoute(path="/api/documents/{document_id}", file="backend/app/main.py", framework="fastapi")],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-ownership",
        agent_type="auth",
        specialist="object-ownership",
        title="BOLA",
        vulnerability_class="bola",
        target_surfaces=["/api/documents/{document_id}"],
        target_files=["backend/app/main.py"],
        reasoning="ownership",
        required_evidence=["handler", "data access"],
        priority="high",
    )
    drafts, _ = run_specialists(runtime, [hypothesis], [], packs, graph)
    assert drafts
    draft = drafts[0]
    assert draft.vulnerability_class == "bola"
    assert draft.graph_path is not None
    result = verify_draft(
        draft,
        _scan_report(repo),
        context_paths={"backend/app/main.py"},
        evidence_packs=packs,
        attack_graph=graph,
    )
    assert result.status == "verified"
    assert result.verified is not None
    assert result.verified.qa_comparison is None


def test_public_readonly_get_route_rejected(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.get('/api/health')\n"
                "async def health():\n"
                "    return {'ok': True}\n"
            ),
        },
        [SurfaceRoute(path="/api/health", file="backend/app/main.py", framework="fastapi")],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-api",
        agent_type="api",
        specialist="api-abuse",
        title="API",
        vulnerability_class="api-abuse",
        target_surfaces=["/api/health"],
        target_files=["backend/app/main.py"],
        reasoning="api",
        required_evidence=["handler"],
        priority="low",
    )
    drafts, rejected = run_specialists(runtime, [hypothesis], [], packs, graph)
    assert not drafts
    assert rejected


def test_service_role_in_request_path_detected(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.post('/api/upload')\n"
                "async def upload_file():\n"
                "    client = create_client(url, SUPABASE_SERVICE_ROLE_KEY)\n"
                "    return client.storage.from_('uploads').upload('file', data)\n"
            ),
        },
        [SurfaceRoute(path="/api/upload", file="backend/app/main.py", framework="fastapi")],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-storage",
        agent_type="storage",
        specialist="storage-access",
        title="Storage",
        vulnerability_class="privilege-escalation",
        target_surfaces=["/api/upload"],
        target_files=["backend/app/main.py"],
        reasoning="storage",
        required_evidence=["service role"],
        priority="high",
    )
    drafts, _ = run_specialists(runtime, [hypothesis], [], packs, graph)
    assert drafts
    assert drafts[0].vulnerability_class == "privilege-escalation"
    assert drafts[0].graph_path is not None


def test_ai_action_without_approval_detected(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.post('/api/run-action')\n"
                "async def run_action(payload: dict = Body(...)):\n"
                "    return openai.chat.completions.create(model='gpt-4', messages=[payload])\n"
            ),
        },
        [SurfaceRoute(path="/api/run-action", file="backend/app/main.py", framework="fastapi")],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-ai",
        agent_type="ai",
        specialist="ai-action-boundary",
        title="AI action",
        vulnerability_class="ai-action-abuse",
        target_surfaces=["/api/run-action"],
        target_files=["backend/app/main.py"],
        reasoning="ai",
        required_evidence=["ai call"],
        priority="high",
    )
    drafts, _ = run_specialists(runtime, [hypothesis], [], packs, graph)
    assert drafts
    assert drafts[0].specialist == "ai-action-boundary"
    assert drafts[0].graph_path is not None


def test_frontend_auth_backend_missing_guard_detected(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "frontend/lib/api.ts": (
                "export function useSession() { return { user: null }; }\n"
                "export async function fetchDocuments() {\n"
                "  return fetch('/api/documents');\n"
                "}\n"
            ),
            "backend/app/main.py": (
                "@app.get('/api/documents')\n"
                "async def list_documents():\n"
                "    return db.session.query(Document).all()\n"
            ),
        },
        [
            SurfaceRoute(path="/api/documents", file="backend/app/main.py", framework="fastapi"),
        ],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-auth",
        agent_type="auth",
        specialist="auth-boundary",
        title="Auth mismatch",
        vulnerability_class="broken-access-control",
        target_surfaces=["/api/documents"],
        target_files=["frontend/lib/api.ts", "backend/app/main.py"],
        reasoning="cross-file auth",
        required_evidence=["frontend auth", "backend handler"],
        priority="high",
    )
    context = [
        RetrievedContext(
            id="c1",
            query_id="q1",
            source_type="file",
            excerpt="useSession",
            score=0.8,
            reason="auth",
            source_path="frontend/lib/api.ts",
            context_category="auth",
        )
    ]
    drafts, _ = run_specialists(runtime, [hypothesis], context, packs, graph)
    assert drafts
    assert drafts[0].graph_path is not None
    assert "frontend" in drafts[0].graph_path.path_description.lower() or "backend" in drafts[0].claim.lower()


def test_verified_findings_require_graph_backed_evidence(tmp_path: Path):
    repo = _repo(
        tmp_path,
        {
            "backend/app/main.py": (
                "@app.get('/api/documents/{document_id}')\n"
                "async def get_document(document_id: str = Path(...)):\n"
                "    return db.session.query(Document).filter_by(id=document_id).first()\n"
            ),
        },
        [SurfaceRoute(path="/api/documents/{document_id}", file="backend/app/main.py", framework="fastapi")],
    )
    runtime = _runtime_input(tmp_path, repo)
    graph, packs = _build_graph_and_packs(tmp_path, repo)
    hypothesis = AttackHypothesis(
        id="hyp-ownership",
        agent_type="auth",
        specialist="object-ownership",
        title="BOLA",
        vulnerability_class="bola",
        target_surfaces=["/api/documents/{document_id}"],
        target_files=["backend/app/main.py"],
        reasoning="ownership",
        required_evidence=["handler", "data access"],
        priority="high",
    )
    drafts, _ = run_specialists(runtime, [hypothesis], [], packs, graph)
    assert drafts
    draft = drafts[0]
    assert draft.graph_path is not None
    assert len(draft.evidence) >= 2
    result = verify_draft(
        draft,
        _scan_report(repo),
        context_paths={"backend/app/main.py"},
        evidence_packs=packs,
        attack_graph=graph,
    )
    assert result.status == "verified"
