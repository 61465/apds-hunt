"""CLI entry point for apds-hunt."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .patch_parser import GitInvocationError, parse_patch_commit
from .reporter import to_json, to_table
from .xor_rule import evaluate_xor_rule


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apds-hunt",
        description=(
            "Asymmetric Patch Detection for Symmetric APIs — "
            "evaluate the XOR Rule against a patch commit to surface sibling functions "
            "that likely still carry the same vulnerability."
        ),
        epilog=(
            "This is the public v0.1 teaching edition. See docs/METHODOLOGY.md for "
            "the IP split and NDA path for the full implementation."
        ),
    )
    parser.add_argument(
        "--repo",
        required=True,
        type=Path,
        help="Path to the git repository containing the patch commit.",
    )
    parser.add_argument(
        "--patch",
        required=True,
        metavar="SHA",
        help="Commit SHA (or ref) of the security patch to analyze.",
    )
    parser.add_argument(
        "--search-path",
        action="append",
        default=[],
        type=Path,
        metavar="PATH",
        help=(
            "Extra directory or file to scan for sibling candidates in addition to "
            "the patched files' own directories. May be repeated."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help="Suppress findings whose baseline confidence is below this threshold.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"apds-hunt {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    repo_path: Path = args.repo
    if not repo_path.exists():
        print(f"apds-hunt: repository path does not exist: {repo_path}", file=sys.stderr)
        return 2
    if not (repo_path / ".git").exists():
        print(
            f"apds-hunt: {repo_path} does not look like a git repository "
            f"(missing .git/).",
            file=sys.stderr,
        )
        return 2

    try:
        patched = parse_patch_commit(repo_path, args.patch)
    except GitInvocationError as exc:
        print(f"apds-hunt: {exc}", file=sys.stderr)
        return 2

    if not patched:
        print(
            f"apds-hunt: commit {args.patch} did not touch any C/C++ function bodies "
            f"this extractor could parse. XOR Rule has nothing to evaluate.",
            file=sys.stderr,
        )
        return 1

    findings = evaluate_xor_rule(
        patched,
        extra_search_paths=args.search_path,
    )

    if args.min_confidence > 0:
        findings = [f for f in findings if f.confidence >= args.min_confidence]

    if args.format == "json":
        print(to_json(findings))
    else:
        print(to_table(findings))

    return 0 if findings else 1


if __name__ == "__main__":
    sys.exit(main())
