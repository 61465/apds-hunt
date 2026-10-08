"""
Public verb-pair dictionary for APDS v0.1.

The pairs listed here are the HISTORICALLY-DOCUMENTED symmetric API pairs
that occur in open-source literature on secure API design (CWE-227,
CERT-C MEM30-C, CWE-911) and the five landmark CVEs documented in the
APDS methodology spec. Each pair is accompanied by its empirical false-
positive risk tier so callers can filter.

The EXPANDED dictionary (industry-specific pairs, protocol-specific pairs,
async-pair variants, cross-language dialect pairs) is retained as a
NEXUS Zone research artifact per the IP split documented in
`docs/METHODOLOGY.md`. Google TAG may request advance NDA access to the
full dictionary via `abdarahman10555@gmail.com`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class VerbPair:
    """A symmetric API verb pair.

    ``left`` and ``right`` are matched as the FIRST token of a function
    identifier split on common separators (camelCase, snake_case, ::). The
    comparison is case-insensitive on the token boundary.
    """

    left: str
    right: str
    # Risk tier for false positives when applied naively (no call-graph context).
    # low   = pair strongly implies symmetry (get/set style)
    # med   = pair is symmetric but overloaded in common usage
    # high  = pair appears in many non-symmetric contexts; needs extra filtering
    fp_risk: str
    # One-line note explaining why this pair qualifies as symmetric for APDS.
    rationale: str


# -----------------------------------------------------------------------
# PUBLIC verb pairs — covers the 5 landmark CVEs validated in the APDS
# methodology spec plus common CWE-227 / CERT-C MEM30-C patterns.
# -----------------------------------------------------------------------
PUBLIC_VERB_PAIRS: tuple[VerbPair, ...] = (
    # Access accessor pair — the "classic" APDS case
    # (CVE-2024-40658 getConfig/setConfig lives here)
    VerbPair("get", "set", "low", "property accessor pair; parent class of CVE-2024-40658"),
    # Lifecycle pairs — unbalanced hardening leaves half of lifecycle unsafe
    VerbPair("create", "destroy", "low", "lifecycle; CWE-911 improper restriction class"),
    VerbPair("alloc", "free", "low", "memory lifecycle; CERT-C MEM30-C"),
    VerbPair("acquire", "release", "low", "resource lifecycle; CWE-404"),
    VerbPair("open", "close", "med", "handle lifecycle; noisy in file i/o"),
    VerbPair("init", "deinit", "low", "object lifecycle"),
    # Serialization pairs — CVE-2016-1646 V8 class
    VerbPair("encode", "decode", "low", "serialization boundary; CVE-2016-1646 class"),
    VerbPair("serialize", "deserialize", "low", "serialization boundary"),
    VerbPair("marshal", "unmarshal", "low", "RPC/network serialization"),
    VerbPair("pack", "unpack", "med", "binary buffer boundary"),
    # Transport pairs — CVE-2015-4000 LogJam class
    VerbPair("send", "receive", "med", "transport boundary; CVE-2015-4000 class"),
    VerbPair("read", "write", "high", "generic i/o; HIGH false-positive risk"),
    # Lock pairs — CWE-667
    VerbPair("lock", "unlock", "low", "mutex/lock pair; CWE-667"),
    # Push/pop pairs — stack-style
    VerbPair("push", "pop", "med", "stack/queue boundary"),
    # Enable/disable pairs — feature-flag boundaries
    VerbPair("enable", "disable", "med", "feature-gate boundary"),
    # Add/remove — collection boundary
    VerbPair("add", "remove", "high", "collection boundary; needs extra filtering"),
    # Insert/delete — index boundary
    VerbPair("insert", "delete", "med", "indexed container boundary"),
    # Attach/detach — handler boundary
    VerbPair("attach", "detach", "low", "handler lifecycle"),
    # Register/unregister — observer boundary
    VerbPair("register", "unregister", "low", "observer lifecycle"),
    # Bind/unbind — binding boundary
    VerbPair("bind", "unbind", "low", "binding lifecycle"),
    # Load/unload — module boundary
    VerbPair("load", "unload", "med", "module lifecycle"),
    # Describe-flavor pair (CVE-2024-40658 fine-grained match)
    # internalGetConfig(kDescribeHdr10PlusInfoIndex) <->
    # internalSetConfig(kDescribeHdr10PlusInfoIndex)
    VerbPair("getConfig", "setConfig", "low", "parameterized accessor; CVE-2024-40658 exact match"),
)


# Token separator conventions seen across C/C++, Java, Rust, Go, Python.
_IDENT_SEPARATORS = ("::", ".", "_")


def _leading_verb_tokens(identifier: str) -> list[str]:
    """Return the plausible leading-verb tokens for an identifier.

    For ``internalSetConfig`` returns ``["internal", "set"]`` so both the
    outer prefix and the camel-cased verb are testable. For ``alloc_pages``
    returns ``["alloc", "pages"]`` so a snake-case verb pair matches.
    """
    bare = identifier
    for sep in _IDENT_SEPARATORS:
        bare = bare.replace(sep, " ")

    tokens: list[str] = []
    buf = ""
    for ch in bare:
        if ch == " ":
            if buf:
                tokens.append(buf)
                buf = ""
            continue
        if ch.isupper() and buf and not buf[-1].isupper():
            tokens.append(buf)
            buf = ch
            continue
        buf += ch
    if buf:
        tokens.append(buf)

    # Lowercase for case-insensitive comparison downstream.
    return [t.lower() for t in tokens if t]


def _bare_name(identifier: str) -> str:
    """Return the identifier with class/namespace qualifiers stripped.

    ``SoftDecoder::internalSetConfig`` -> ``internalSetConfig``,
    ``ns::ClassX::doThing``             -> ``doThing``.
    Qualified pieces are irrelevant to the APDS verb-pair match — the pair
    binds on the function's own name, not its enclosing scope.
    """
    bare = identifier
    for sep in ("::", "."):
        if sep in bare:
            bare = bare.rsplit(sep, 1)[-1]
    return bare


def _bare_tokens(identifier: str) -> list[str]:
    """Tokenize an identifier's bare name only (no class/namespace prefix)."""
    return _leading_verb_tokens(_bare_name(identifier))


def _leading_verb(identifier: str) -> str | None:
    """Best-guess leading verb token for ``identifier`` (bare-name only)."""
    tokens = _bare_tokens(identifier)
    return tokens[0] if tokens else None


def find_sibling_candidates(
    patched_identifier: str,
    other_identifiers: Iterable[str],
    pairs: Iterable[VerbPair] = PUBLIC_VERB_PAIRS,
) -> list[tuple[str, VerbPair]]:
    """Return identifiers that look like symmetric siblings of ``patched_identifier``.

    A sibling must (a) differ from the patched identifier by exactly one
    token that forms a known verb pair, (b) agree on the surrounding
    tokens (prefix + suffix) of the bare identifier, and (c) share the
    class/namespace qualifier so unrelated classes don't collide.

    APDS matches verb pairs anywhere inside the bare name — so both
    ``getConfig`` ↔ ``setConfig`` (position 0) and
    ``internalGetConfig`` ↔ ``internalSetConfig`` (position 1) resolve
    through the same code path. Case-insensitive on the verb token
    boundary; preserves input casing in the output.
    """
    patched_bare_tokens = _bare_tokens(patched_identifier)
    if not patched_bare_tokens:
        return []
    patched_qualifier = patched_identifier[: -len(_bare_name(patched_identifier))]

    pair_list = tuple(pairs)
    # Precompute lowercased verbs once per pair.
    pair_verbs = [(p.left.lower(), p.right.lower(), p) for p in pair_list]

    results: list[tuple[str, VerbPair]] = []
    seen: set[tuple[str, tuple[str, str]]] = set()

    for candidate in other_identifiers:
        if candidate == patched_identifier:
            continue
        candidate_qualifier = candidate[: -len(_bare_name(candidate))]
        if candidate_qualifier != patched_qualifier:
            # Sibling discovery only matches within the same enclosing scope.
            # Cross-class pairs are intentionally out of v0.1 scope — the
            # expanded dictionary handles those via trust-boundary analysis
            # retained per the IP split.
            continue
        candidate_tokens = _bare_tokens(candidate)
        if len(candidate_tokens) != len(patched_bare_tokens):
            continue

        diff_positions = [
            i
            for i, (lt, rt) in enumerate(zip(patched_bare_tokens, candidate_tokens))
            if lt != rt
        ]
        if len(diff_positions) != 1:
            continue
        pos = diff_positions[0]
        patched_verb = patched_bare_tokens[pos]
        candidate_verb = candidate_tokens[pos]
        for left, right, pair in pair_verbs:
            if {patched_verb, candidate_verb} == {left, right}:
                key = (candidate, (left, right))
                if key in seen:
                    break
                seen.add(key)
                results.append((candidate, pair))
                break
    return results
