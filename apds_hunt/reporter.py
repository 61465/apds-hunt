"""Formatting for apds-hunt findings."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .xor_rule import XORFinding


def to_json(findings: Iterable[XORFinding]) -> str:
    """Serialize findings as a stable, machine-readable JSON array."""
    payload = []
    for finding in findings:
        payload.append(
            {
                "patched": {
                    "path": finding.patched_function.path,
                    "qualified_name": finding.patched_function.qualified_name,
                    "line_start": finding.patched_function.line_start,
                    "line_end": finding.patched_function.line_end,
                },
                "sibling": {
                    "path": finding.sibling_function.path,
                    "qualified_name": finding.sibling_function.qualified_name,
                    "line_start": finding.sibling_function.line_start,
                    "line_end": finding.sibling_function.line_end,
                },
                "pair": asdict(finding.pair),
                "confidence": round(finding.confidence, 3),
                "rationale": finding.rationale,
            }
        )
    return json.dumps(payload, indent=2, sort_keys=False)


def to_table(findings: Iterable[XORFinding]) -> str:
    """Render findings as a plain-text table suitable for a terminal."""
    rows = list(findings)
    if not rows:
        return "No APDS findings. XOR Rule found no un-patched symmetric siblings."

    header = (
        f"{'CONF':>5} | {'VERB PAIR':<22} | {'PATCHED (g1)':<48} | {'SIBLING (g2 — review)':<48}"
    )
    separator = "-" * len(header)
    lines = [header, separator]
    for finding in rows:
        pair_label = f"{finding.pair.left}/{finding.pair.right}"
        lines.append(
            f"{finding.confidence:>5.2f} | {pair_label:<22} | "
            f"{finding.patched_function.qualified_name[:48]:<48} | "
            f"{finding.sibling_function.qualified_name[:48]:<48}"
        )
    lines.append("")
    lines.append(
        "APDS XOR Rule — each row is a sibling g2 that did NOT receive the hardening added to g1."
    )
    lines.append("Review each candidate against the patch's security intent.")
    return "\n".join(lines)
