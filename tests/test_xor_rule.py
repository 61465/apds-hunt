"""Unit tests for the XOR Rule evaluator.

These tests exercise the full pipeline end-to-end against a hand-crafted
mini-repo that reproduces the CVE-2024-40658 shape: an ``internalGetConfig``
hardened by a patch, and an unpatched sibling ``internalSetConfig`` sitting
in the same file.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from apds_hunt.patch_parser import parse_patch_commit
from apds_hunt.xor_rule import evaluate_xor_rule


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> None:
    """Run ``git`` with deterministic author/committer identity for tests."""
    full_env = {
        "GIT_AUTHOR_NAME": "APDS Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "APDS Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    if env:
        full_env.update(env)
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env={**full_env},
    )


@pytest.fixture
def cve_2024_40658_shape(tmp_path: Path) -> tuple[Path, str]:
    """Build a mini-repo that mirrors the CVE-2024-40658 asymmetric patch shape.

    Returns ``(repo_path, patch_sha)``. The pre-patch tree holds BOTH
    ``internalGetConfig`` and ``internalSetConfig`` with equally weak
    bounds handling. The patch adds a bounds check only to the getter —
    exactly the shape APDS is designed to flag.
    """
    repo = tmp_path / "mini-aosp"
    repo.mkdir()
    _git(repo, "init", "-q", "--initial-branch=main")

    src_dir = repo / "frameworks"
    src_dir.mkdir()
    src_path = src_dir / "SoftVideoDecoderOMXComponent.cpp"
    pre_patch = (
        "// Minimal fixture for apds-hunt CVE-2024-40658 shape\n"
        "struct Params { int sizeUsed; };\n"
        "\n"
        "int SoftVideoDecoderOMXComponent::internalGetConfig(int idx, Params* p) {\n"
        "    copyOut(p->sizeUsed);\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int SoftVideoDecoderOMXComponent::internalSetConfig(int idx, const Params* p) {\n"
        "    copyIn(p->sizeUsed);\n"
        "    return 0;\n"
        "}\n"
    )
    src_path.write_text(pre_patch, encoding="utf-8")

    _git(repo, "add", "frameworks/SoftVideoDecoderOMXComponent.cpp")
    _git(repo, "commit", "-q", "-m", "initial")

    post_patch = (
        "// Minimal fixture for apds-hunt CVE-2024-40658 shape\n"
        "struct Params { int sizeUsed; };\n"
        "static const int kMaxParamSize = 1024;\n"
        "\n"
        "int SoftVideoDecoderOMXComponent::internalGetConfig(int idx, Params* p) {\n"
        "    if (p->sizeUsed > kMaxParamSize) return -1;\n"
        "    copyOut(p->sizeUsed);\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int SoftVideoDecoderOMXComponent::internalSetConfig(int idx, const Params* p) {\n"
        "    copyIn(p->sizeUsed);\n"
        "    return 0;\n"
        "}\n"
    )
    src_path.write_text(post_patch, encoding="utf-8")

    _git(repo, "add", "frameworks/SoftVideoDecoderOMXComponent.cpp")
    _git(repo, "commit", "-q", "-m", "fix: bounds-check sizeUsed in internalGetConfig (b/329641908)")

    rev = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return repo, rev.stdout.strip()


class TestXORRuleEndToEnd:
    def test_cve_2024_40658_shape_detected(self, cve_2024_40658_shape):
        repo, sha = cve_2024_40658_shape
        patched = parse_patch_commit(repo, sha)
        assert any(
            pf.definition.name == "internalGetConfig" for pf in patched
        ), "patch should have touched internalGetConfig"

        findings = evaluate_xor_rule(patched)

        assert len(findings) == 1, f"expected exactly one XOR finding, got {findings}"
        f = findings[0]
        assert f.patched_function.name == "internalGetConfig"
        assert f.sibling_function.name == "internalSetConfig"
        assert (f.pair.left, f.pair.right) == ("get", "set")
        assert f.confidence >= 0.8, "same-file get/set pair should score high"

    def test_no_findings_when_both_sides_patched(self, tmp_path: Path):
        """XOR Rule invariant: if BOTH g1 and g2 are in P, the finding must NOT emit."""
        repo = tmp_path / "symmetric"
        repo.mkdir()
        _git(repo, "init", "-q", "--initial-branch=main")

        src = repo / "a.cpp"
        src.write_text(
            "int getX() { return 0; }\n\nint setX(int x) { return x; }\n",
            encoding="utf-8",
        )
        _git(repo, "add", "a.cpp")
        _git(repo, "commit", "-q", "-m", "initial")

        src.write_text(
            (
                "int getX() { if (bad()) return -1; return 0; }\n\n"
                "int setX(int x) { if (bad()) return -1; return x; }\n"
            ),
            encoding="utf-8",
        )
        _git(repo, "add", "a.cpp")
        _git(repo, "commit", "-q", "-m", "fix: harden both sides")

        rev = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        findings = evaluate_xor_rule(parse_patch_commit(repo, rev))
        assert findings == [], "both-sides patched must produce no XOR findings"

    def test_findings_sorted_by_confidence_desc(self, cve_2024_40658_shape):
        """Reporter contract: higher-confidence findings come first."""
        repo, sha = cve_2024_40658_shape
        findings = evaluate_xor_rule(parse_patch_commit(repo, sha))
        confidences = [f.confidence for f in findings]
        assert confidences == sorted(confidences, reverse=True)
