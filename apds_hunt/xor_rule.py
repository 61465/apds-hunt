"""
The APDS XOR Rule — core discovery predicate.

From the methodology spec (``docs/METHODOLOGY.md``):

    For any pair (g₁, g₂) ∈ F × F with g₁ ~ g₂:
        (g₁, g₂) is a zero-day survivor ⟺ (g₁ ∈ P) XOR (g₂ ∈ P)

v0.1 ships the Boolean predicate exactly as stated. The IP-protected
elements — call-graph propagation depth tuning, patch-metadata heuristic,
semantic-equivalence ML fallback, prioritization formula weights — are
retained per the IP split in ``docs/METHODOLOGY.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .function_extractor import FunctionDefinition, extract_functions
from .patch_parser import PatchedFunction
from .verb_pairs import PUBLIC_VERB_PAIRS, VerbPair, find_sibling_candidates


@dataclass(frozen=True)
class XORFinding:
    """A single APDS zero-day-survivor candidate.

    - ``patched_function`` is ``g₁``: the function the patch commit modified.
    - ``sibling_function`` is ``g₂``: the symmetric partner that did NOT
      receive the equivalent hardening.
    - ``pair`` names the verb pair that bound ``g₁`` and ``g₂`` as siblings.
    - ``confidence`` is a shallow 0.0-1.0 score. The expanded prioritization
      formula (CVSS × propagation depth × exploitable-pattern × recency) is
      retained; this baseline uses only the verb-pair's false-positive risk
      tier and whether the pair is co-located in the same file.
    """

    patched_function: FunctionDefinition
    sibling_function: FunctionDefinition
    pair: VerbPair
    confidence: float
    rationale: str


def _baseline_confidence(pair: VerbPair, same_file: bool) -> float:
    """Shallow confidence scorer; see class docstring for the retained parts."""
    base = {"low": 0.80, "med": 0.55, "high": 0.30}.get(pair.fp_risk, 0.30)
    if same_file:
        base += 0.10
    return min(base, 0.95)


def evaluate_xor_rule(
    patched: Iterable[PatchedFunction],
    *,
    extra_search_paths: Iterable[Path | str] = (),
    verb_pairs: Iterable[VerbPair] = PUBLIC_VERB_PAIRS,
) -> list[XORFinding]:
    """Evaluate the XOR Rule over a patch's touched functions.

    For every patched function ``g₁``, look in the same file (and any
    ``extra_search_paths`` the caller supplies) for an identifier that
    matches a known verb pair. If such a sibling ``g₂`` exists AND the
    patch did NOT touch its body, emit an :class:`XORFinding`.

    Note: this baseline only checks co-location (same file, extra paths).
    The call-graph propagation that handles patches reaching siblings
    *indirectly* (via a shared helper or chained caller) is retained per
    the IP split; v0.1 reports those cases as misses rather than claiming
    an unsound result.
    """
    patched_list = list(patched)
    patched_identifiers = {pf.definition.qualified_name for pf in patched_list}
    pair_list = tuple(verb_pairs)

    # Build a path -> definitions index so we only extract each file once.
    file_defs: dict[str, list[FunctionDefinition]] = {}

    def defs_in(path: str) -> list[FunctionDefinition]:
        cached = file_defs.get(path)
        if cached is not None:
            return cached
        resolved = extract_functions(path)
        file_defs[path] = resolved
        return resolved

    findings: list[XORFinding] = []
    for pf in patched_list:
        g1_defn = pf.definition
        search_paths: list[str] = [g1_defn.path]
        for extra in extra_search_paths:
            extra_str = str(extra)
            if extra_str not in search_paths:
                search_paths.append(extra_str)

        for path in search_paths:
            candidates = defs_in(path)
            candidate_names = [c.qualified_name for c in candidates]
            siblings = find_sibling_candidates(g1_defn.qualified_name, candidate_names, pair_list)
            for sibling_name, pair in siblings:
                # XOR Rule: sibling must NOT be in the patched set.
                if sibling_name in patched_identifiers:
                    continue
                sibling_defn = next(
                    (c for c in candidates if c.qualified_name == sibling_name),
                    None,
                )
                if sibling_defn is None:
                    continue
                same_file = sibling_defn.path == g1_defn.path
                confidence = _baseline_confidence(pair, same_file)
                findings.append(
                    XORFinding(
                        patched_function=g1_defn,
                        sibling_function=sibling_defn,
                        pair=pair,
                        confidence=confidence,
                        rationale=(
                            f"XOR Rule: patched '{g1_defn.qualified_name}' is in P; "
                            f"sibling '{sibling_defn.qualified_name}' is NOT in P "
                            f"(verb pair {pair.left!r}/{pair.right!r}, fp_risk={pair.fp_risk})."
                        ),
                    )
                )

    # Highest confidence first for stable reporting.
    findings.sort(key=lambda f: f.confidence, reverse=True)
    return findings
