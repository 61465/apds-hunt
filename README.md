# apds-hunt

**Reference implementation of the APDS methodology — Asymmetric Patch Detection for Symmetric APIs.**

`apds-hunt` evaluates the **XOR Rule** against a security-patch commit and surfaces sibling functions in the same codebase that likely still carry the same vulnerability. The methodology was first applied in Google Android VRP submission [#571135577](https://issuetracker.google.com/issues/571135577) to find a byte-identical un-patched sibling of CVE-2024-40658 across six AOSP release branches.

This repository is the **public teaching edition (v0.1)** of the tool. The methodology itself is fully documented in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md); a subset of the implementation (expanded verb-pair dictionary, call-graph propagation, ML-embedding semantic fallback, prioritization-formula weights, cross-language indexing) is retained as a NEXUS Zone research artifact. See the [IP split](#whats-public-vs-whats-retained) table below.

---

## The XOR Rule in one line

> For any pair of semantically-symmetric functions `(g₁, g₂)` in a codebase with patch set `P`:
>
> ```
> (g₁, g₂) is a zero-day survivor ⟺ (g₁ ∈ P) XOR (g₂ ∈ P)
> ```

In plain English: if a security patch hardens one half of a symmetric API pair (`getX` / `setX`, `encode` / `decode`, `acquire` / `release`, …) but not the other, the un-hardened half is a candidate zero-day survivor until it's audited.

---

## Install

```bash
pip install apds-hunt
```

Requires Python ≥ 3.10 and `git` on `PATH`. The package has no runtime dependencies beyond the standard library.

From source:

```bash
git clone https://github.com/61465/apds-hunt
cd apds-hunt
pip install -e .[dev]
pytest -v
```

---

## Quick start

Point it at a cloned repository and the SHA of a security patch:

```bash
apds-hunt --repo ./external/libpng --patch a1b2c3d
```

Example output:

```
 CONF | VERB PAIR              | PATCHED (g1)                                     | SIBLING (g2 — review)
---------------------------------------------------------------------------------------------------------
 0.90 | get/set                | SoftDecoder::internalGetConfig                   | SoftDecoder::internalSetConfig
```

For a machine-readable report:

```bash
apds-hunt --repo ./external/libpng --patch a1b2c3d --format json
```

Full option reference: [`docs/USAGE.md`](docs/USAGE.md).

---

## What's public vs. what's retained

The APDS methodology is a formal, auditable, mathematically-founded discovery predicate. The algorithm is fully documented. A subset of the engineering is retained for research-artifact reasons documented in the Google ASR submission.

| Element | v0.1 (public) | Retained |
|---|:---:|:---:|
| XOR Rule theorem + 6-step algorithm | ✅ | — |
| CVE-2024-40658 case study + 5 landmark CVE validations | ✅ | — |
| Core verb-pair dictionary (21 pairs, covers landmark CVEs) | ✅ | — |
| Expanded verb-pair dictionary (industry-, protocol-, async-pair variants) | — | ✅ |
| Boolean XOR evaluator | ✅ | — |
| Regex-based C/C++ function extractor | ✅ | — |
| libclang / tree-sitter / javaparser indexing adapters | — | ✅ |
| Direct same-scope sibling discovery | ✅ | — |
| Forward call-graph propagation (depth tuning) | — | ✅ |
| Patch-metadata heuristic (CVE / Bug: / Fixes: mining) | — | ✅ |
| ML-embedding semantic fallback for sibling discovery | — | ✅ |
| Prioritization formula weights (CVSS × depth × exploitable-pattern × recency) | — | ✅ |
| Historical case corpus used to derive the methodology | — | ✅ |

**NDA path for Google TAG and security-team collaboration**: `abdarahman10555@gmail.com`.

---

## Methodology at a glance

APDS is built on a single structural observation about large-scale software maintenance:

> When a security vulnerability affects a function `g₁` that has a semantic sibling `g₂` in the same API pair, remediation patches frequently address only ONE side of the pair, leaving identical attack surface in the sibling for extended survival windows (empirically **12–36 months** in production codebases).

The methodology formalizes that observation as the XOR Rule, retrospectively detects it in five landmark CVEs (BlueBorne 2017, Stagefright 2015, LogJam 2015, V8 CVE-2016-1646, HDR10+ 2024), and demonstrates its first prospective application through the discovery documented in Google Android VRP #571135577.

Full specification: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

---

## Honest limitations of v0.1

The public edition deliberately ships a **shallow baseline** so the methodology is understandable and verifiable without exposing the engineering IP. These limits are expected:

- **C/C++ only.** The regex-based extractor handles common function definition shapes. Templates with elaborate meta-programming, macro-expanded bodies, and function pointers are not captured. Falls open on misses (false negatives), never on garbage (false positives).
- **Direct siblings only.** v0.1 looks for a sibling inside the same file / `--search-path`. Patches that reach a sibling via a shared helper or a forward-call-graph chain are not detected here (propagation is retained).
- **No ML fallback.** Siblings whose names don't match the public verb pairs are not surfaced in v0.1 even when they are semantically symmetric.
- **No prioritization weights.** `confidence` is a baseline from the verb-pair's documented false-positive risk tier plus co-location. The expanded prioritization (CVSS × propagation depth × exploitable-pattern × recency) is retained.

Despite the limits, v0.1 correctly reproduces the CVE-2024-40658 shape end-to-end — see `tests/test_xor_rule.py::test_cve_2024_40658_shape_detected`.

---

## Research artifact

This repository, together with [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md), is the citable artifact for the APDS methodology.

- **Framework version**: 1.0
- **First application**: Google Android VRP [#571135577](https://issuetracker.google.com/issues/571135577) — CVE-2024-40658 symmetric sibling, CVSS 10.0 Critical
- **Author**: Abdalrahman Mohamed, NEXUS Zone Research
- **Correspondence**: `abdarahman10555@gmail.com`
- **License**: MIT

An academic paper is in preparation for submission to USENIX / IEEE S&P / CCS.

---

## Contributing

Issues and pull requests are welcome. Please file an issue first before sending non-trivial changes so we can discuss scope — in particular, additions to the public verb-pair dictionary should ship with (a) the landmark CVE or canonical API pair that justifies inclusion, and (b) a false-positive risk tier assessment.

Security-sensitive communication: `abdarahman10555@gmail.com`.

---

## Acknowledgements

- **Google Android Security team** (ASR panel) — for the collaboration channel that catalyzed the formalization of APDS as a methodology rather than a one-off finding.
- **rrweb-io / @eoghanmurray** — unrelated to this project, but recent upstream work on `MutationBuffer` is a textbook example of why APDS matters: a security-adjacent performance patch can leave sibling code paths vulnerable for years before anyone notices. (Observation only; no claim about rrweb specifically.)
- All researchers whose landmark CVE write-ups made the retrospective validation possible.
