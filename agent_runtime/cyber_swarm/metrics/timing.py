"""Stage timing helpers for runtime instrumentation."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Iterator


@contextmanager
def stage_timer(
    metrics: dict[str, Any],
    stage: str,
) -> Iterator[None]:
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        timings = dict(metrics.get("stageTimings", {}))
        timings[stage] = elapsed_ms
        metrics["stageTimings"] = timings


def merge_stage_timing(
    metrics: dict[str, Any],
    stage: str,
    elapsed_ms: float,
) -> dict[str, Any]:
    updated = dict(metrics)
    timings = dict(updated.get("stageTimings", {}))
    timings[stage] = round(elapsed_ms, 2)
    updated["stageTimings"] = timings
    return updated


def estimate_tokens(text: str) -> int:
    """Rough input token estimate (~4 chars per token)."""
    if not text:
        return 0
    return max(1, len(text) // 4)
