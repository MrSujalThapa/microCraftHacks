"""CLI entrypoint for the Cyber Swarm Python agent runtime."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyber_swarm.bridge import run_bridge
from cyber_swarm.models.runtime_config import RuntimeConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber_swarm.runner",
        description="Cyber Swarm Python agent runtime",
    )
    parser.add_argument(
        "--scan-report",
        type=Path,
        help="Path to TypeScript scan report JSON",
    )
    parser.add_argument(
        "--routed-skills",
        type=Path,
        help="Path to routed skills JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path to write findings output JSON",
    )
    parser.add_argument(
        "--provider",
        default="mock",
        choices=["mock", "openai", "local"],
        help="Model provider to use for agent stages",
    )
    parser.add_argument(
        "--model",
        default="gpt-5-mini",
        help="Model name when using an LLM provider",
    )
    parser.add_argument(
        "--max-selected-context",
        type=int,
        default=8,
        help="Maximum selected retrieval context items for smoke runs",
    )
    parser.add_argument(
        "--max-draft-findings",
        type=int,
        default=3,
        help="Maximum draft findings to keep for smoke runs",
    )
    parser.add_argument(
        "--call-timeout",
        type=float,
        default=60.0,
        help="Timeout in seconds for each model call",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.scan_report is None and args.routed_skills is None and args.output is None:
        return 0

    missing = [
        flag
        for flag, value in (
            ("--scan-report", args.scan_report),
            ("--routed-skills", args.routed_skills),
            ("--output", args.output),
        )
        if value is None
    ]
    if missing:
        parser.error(f"All bridge flags are required when invoking the runtime: {', '.join(missing)}")

    runtime_config = RuntimeConfig(
        provider=args.provider,
        model=args.model,
        max_selected_context=args.max_selected_context,
        max_draft_findings=args.max_draft_findings,
        call_timeout_seconds=args.call_timeout,
    )
    run_bridge(args.scan_report, args.routed_skills, args.output, runtime_config=runtime_config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
