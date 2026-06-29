"""Tests for retrieval quality gating."""

from __future__ import annotations

from pathlib import Path

from cyber_swarm.models.repo import (
    FileInventoryItem,
    InventoryResult,
    RepoIntelligence,
    SurfaceRoute,
    SurfacesResult,
)
from cyber_swarm.rag.categories import classify_path, is_test_path
from cyber_swarm.rag.code_retrieval import search_code
from cyber_swarm.rag.loop import finalize_context
from cyber_swarm.models.retrieval import RetrievedContext


def test_is_test_path_detects_common_patterns():
    assert is_test_path("src/scanner/surfaces.test.ts")
    assert is_test_path("tests/unit/auth.test.py")
    assert not is_test_path("src/auth.ts")


def test_search_code_prefers_production_over_tests(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "auth.ts").write_text("export function requireAuth() {}\n", encoding="utf-8")
    (src_dir / "auth.test.ts").write_text("describe('auth', () => {})\n", encoding="utf-8")

    repo = RepoIntelligence(
        version="0.1.0",
        scanned_at="2026-06-29T12:00:00.000Z",
        project_root=str(tmp_path),
        inventory=InventoryResult(
            total_files=2,
            by_category={"typescript": 2},
            files=[
                FileInventoryItem(path="src/auth.ts", category="typescript"),
                FileInventoryItem(path="src/auth.test.ts", category="typescript"),
            ],
        ),
        surfaces=SurfacesResult(
            api=[SurfaceRoute(path="/api/login", file="src/auth.ts", framework="express")]
        ),
    )

    results = search_code("auth login middleware", repo)

    assert results
    assert results[0].source_path == "src/auth.ts"
    assert results[0].context_category in {"source", "auth", "route"}
    assert all(result.source_path != "src/auth.test.ts" or result.is_supporting for result in results)


def test_finalize_context_ranks_production_first():
    results = [
        RetrievedContext(
            id="1",
            query_id="q1",
            source_type="file",
            excerpt="test",
            score=0.9,
            reason="test hit",
            source_path="src/foo.test.ts",
            context_category="test",
        ),
        RetrievedContext(
            id="2",
            query_id="q1",
            source_type="file",
            excerpt="prod",
            score=0.6,
            reason="prod hit",
            source_path="src/foo.ts",
            context_category="source",
        ),
    ]

    selected = finalize_context(results, max_items=2)

    assert selected[0].source_path == "src/foo.ts"
    assert classify_path("src/middleware/auth.ts") == "auth"
