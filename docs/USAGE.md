# apds-hunt — usage

## Install

```bash
pip install apds-hunt      # requires Python >= 3.10 and git on PATH
```

Or from source:

```bash
git clone https://github.com/61465/apds-hunt
cd apds-hunt
pip install -e .[dev]
pytest -v
```

## CLI reference

```
apds-hunt --repo <path> --patch <commit-sha> [--format table|json]
         [--min-confidence FLOAT] [--search-path PATH]...
```

| Option | Required | Description |
|---|---|---|
| `--repo` | yes | Path to the git working tree containing the patch commit. |
| `--patch` | yes | Commit SHA (or any ref `git show` accepts) of the security patch. |
| `--format` | no | `table` (default) or `json`. |
| `--min-confidence` | no | Filter findings below this baseline score (0.0–1.0). |
| `--search-path` | no | Additional file or directory to search for sibling candidates. May be repeated. |

Exit codes:

- `0` — one or more APDS findings emitted
- `1` — no findings (either the commit touched no C/C++ bodies the extractor could parse, or the XOR Rule did not fire)
- `2` — input error (missing repo, bad commit, git invocation failure)

## Example: CVE-2024-40658 shape

```bash
git clone https://android.googlesource.com/platform/frameworks/av
apds-hunt --repo av --patch 6d23fa05a40e5462d4b9bad28afa932e6e12a4f3 --format json
```

Expected shape of a finding:

```json
[
  {
    "patched": {
      "path": "...SoftVideoDecoderOMXComponent.cpp",
      "qualified_name": "SoftVideoDecoderOMXComponent::internalGetConfig",
      "line_start": 605,
      "line_end": 686
    },
    "sibling": {
      "path": "...SoftVideoDecoderOMXComponent.cpp",
      "qualified_name": "SoftVideoDecoderOMXComponent::internalSetConfig",
      "line_start": 688,
      "line_end": 762
    },
    "pair": {
      "left": "get",
      "right": "set",
      "fp_risk": "low",
      "rationale": "property accessor pair; parent class of CVE-2024-40658"
    },
    "confidence": 0.9,
    "rationale": "XOR Rule: patched '...::internalGetConfig' is in P; sibling '...::internalSetConfig' is NOT in P (verb pair 'get'/'set', fp_risk=low)."
  }
]
```

Review each `sibling` as if it were an independent code-review finding — the XOR Rule tells you the hardening added to `g₁` is missing from `g₂`, but the final impact assessment is still a human decision.

## Programmatic use

```python
from pathlib import Path
from apds_hunt import evaluate_xor_rule, parse_patch_commit

patched = parse_patch_commit(Path("./external/libpng"), "a1b2c3d")
findings = evaluate_xor_rule(patched)

for f in findings:
    print(f.patched_function.qualified_name, "->", f.sibling_function.qualified_name, f.confidence)
```

## False-positive triage

Baseline `confidence` combines the verb-pair's documented false-positive risk tier with same-file co-location:

- `low` fp_risk + same file → ~0.90
- `low` fp_risk + different file → ~0.80
- `med` fp_risk + same file → ~0.65
- `high` fp_risk + any → ~0.30-0.40

`high` fp_risk pairs (`read` / `write`, `add` / `remove`) are included because they cover real symmetric APIs, but they need the extra scope-and-signature filtering retained in the full implementation. If you're triaging a `high` fp_risk finding manually, inspect:

1. Do `g₁` and `g₂` take mirror-compatible argument types?
2. Do they operate on the same trust boundary?
3. Does the patch to `g₁` protect against a precondition that could also hold at `g₂`'s entry?

If all three are "yes", treat the finding as a credible candidate.
