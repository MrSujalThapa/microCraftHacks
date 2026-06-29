"""CLI entrypoint for the Cyber Swarm Python agent runtime."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyber_swarm.bridge import run_bridge


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

    run_bridge(args.scan_report, args.routed_skills, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
