"""
Parse a patch commit's unified diff and derive the set of functions whose
bodies the patch touched.

v0.1 uses ``git show --unified=0`` to get hunk-boundary information and
cross-references hunk line numbers against the function definitions
extracted from the POST-patch tree (via :mod:`apds_hunt.function_extractor`).
A function is considered "patched" if at least one of its lines falls
inside a hunk that added OR removed code.

More sophisticated patch-metadata heuristics (e.g. mining ``Bug:`` /
``Fixes:`` / CVE references to filter non-security commits, or
propagation along the forward call graph) are retained as NEXUS Zone
research artifacts per the IP split documented in `docs/METHODOLOGY.md`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .function_extractor import FunctionDefinition, extract_functions


@dataclass(frozen=True)
class PatchHunk:
    """A single unified-diff hunk against a specific target file."""

    target_path: str
    new_start: int
    new_count: int


@dataclass(frozen=True)
class PatchedFunction:
    """A function definition whose body was altered by the patch commit."""

    definition: FunctionDefinition
    overlapping_hunks: tuple[PatchHunk, ...]


# Matches diff file headers like ``+++ b/path/to/file.cpp``.
_PLUS_FILE_RE = re.compile(r"^\+\+\+\s+b/(?P<path>.+?)\s*$")
# Matches hunk headers like ``@@ -1,5 +12,3 @@`` or ``@@ -1 +12 @@``.
_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+"
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@"
)


class GitInvocationError(RuntimeError):
    """Raised when ``git show`` fails (missing commit, invalid repo)."""


def _run_git(repo_path: Path, args: list[str]) -> str:
    """Invoke ``git`` inside ``repo_path`` and return stdout as text."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise GitInvocationError("git executable not found on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise GitInvocationError(
            f"git {' '.join(args)} failed: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc
    return completed.stdout


def _parse_unified_diff(diff_text: str) -> list[PatchHunk]:
    """Walk a unified-diff string and emit one :class:`PatchHunk` per hunk."""
    hunks: list[PatchHunk] = []
    current_target: str | None = None
    for line in diff_text.splitlines():
        plus_match = _PLUS_FILE_RE.match(line)
        if plus_match:
            path = plus_match.group("path")
            current_target = None if path == "/dev/null" else path
            continue
        hunk_match = _HUNK_HEADER_RE.match(line)
        if hunk_match and current_target is not None:
            new_count_str = hunk_match.group("new_count")
            new_count = int(new_count_str) if new_count_str is not None else 1
            hunks.append(
                PatchHunk(
                    target_path=current_target,
                    new_start=int(hunk_match.group("new_start")),
                    new_count=new_count,
                )
            )
    return hunks


def _hunks_overlapping(
    hunks: list[PatchHunk], target_path: str, line_start: int, line_end: int
) -> tuple[PatchHunk, ...]:
    """Return the subset of ``hunks`` that intersect ``[line_start, line_end]``."""
    overlapping: list[PatchHunk] = []
    for hunk in hunks:
        if hunk.target_path != target_path:
            continue
        hunk_last = hunk.new_start + max(hunk.new_count - 1, 0)
        if hunk.new_start > line_end or hunk_last < line_start:
            continue
        overlapping.append(hunk)
    return tuple(overlapping)


def parse_patch_commit(
    repo_path: Path | str, commit_sha: str, *, source_suffixes: tuple[str, ...] = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
) -> list[PatchedFunction]:
    """Return every function in ``commit_sha`` whose body a hunk altered.

    The caller supplies the git ``commit_sha`` whose diff is treated as the
    "patch" ``P`` in the XOR Rule. The post-patch tree is used to re-extract
    function definitions so line numbers in the returned hunks line up with
    the versions a developer is reading today.
    """
    repo = Path(repo_path)
    diff_text = _run_git(repo, ["show", "--unified=0", "--no-color", commit_sha])
    hunks = _parse_unified_diff(diff_text)

    changed_files = sorted({hunk.target_path for hunk in hunks})
    patched: list[PatchedFunction] = []
    for rel_path in changed_files:
        if source_suffixes and not rel_path.endswith(source_suffixes):
            continue
        abs_path = repo / rel_path
        if not abs_path.is_file():
            # File was deleted by this commit; nothing to extract from.
            continue
        for defn in extract_functions(abs_path):
            overlap = _hunks_overlapping(hunks, rel_path, defn.line_start, defn.line_end)
            if overlap:
                patched.append(PatchedFunction(definition=defn, overlapping_hunks=overlap))
    return patched
