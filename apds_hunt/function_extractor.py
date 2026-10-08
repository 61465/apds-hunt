"""
Regex-based C/C++ function extractor for APDS v0.1.

v0.1 ships a deliberately-shallow extractor that locates top-level and
member function definitions by walking brace balance. Production-grade
extraction via libclang (handles templates, macros, lambdas, multi-line
return types) is retained as a NEXUS Zone research artifact per the IP
split documented in `docs/METHODOLOGY.md`.

What this extractor WILL find:
- Top-level C/C++ function definitions of the form
  ``[static|inline|template<...>] return-type name(args) {``
- Member function definitions of the form
  ``return-type class::method(args) {``

What this extractor will NOT catch (document the limits honestly):
- Macros that expand into function bodies
- Function pointers aliased by typedef
- Function-template specializations with complex syntax
- Lambdas assigned to names

For out-of-scope cases the extractor conservatively declines to produce a
record (false negatives) rather than emit garbage (false positives). The
XOR Rule only loses sensitivity on missed functions, not soundness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


# Regex intentionally conservative: identifier, optional ``class::`` prefix,
# argument list, open-brace. Anchored to the start of a line (after optional
# whitespace) so we skip calls and declarations.
_FUNCTION_HEAD_RE = re.compile(
    r"""
    ^\s*
    (?:template\s*<[^>]*>\s*)?    # optional template header
    (?:(?:inline|static|constexpr|virtual|explicit|friend)\s+)*
    (?P<return_type>
        (?:[a-zA-Z_][\w:*&<>\s]*?)   # return type (lazy to avoid eating name)
    )
    \s+
    (?P<qualified_name>
        (?:[a-zA-Z_]\w*::)*          # optional class qualifiers
        (?:~?[a-zA-Z_]\w*|operator\s*[^\s(]+) # name or operator
    )
    \s*
    \(                                # open parenthesis of args
    """,
    re.VERBOSE | re.MULTILINE,
)


@dataclass(frozen=True)
class FunctionDefinition:
    """A function definition located in a source file.

    - ``name`` is the bare identifier (e.g. ``internalGetConfig``).
    - ``qualified_name`` preserves class prefixes
      (e.g. ``SoftVideoDecoderOMXComponent::internalGetConfig``).
    - ``line_start`` / ``line_end`` are 1-based line numbers that bracket
      the function body (open brace line through matching close brace).
    - ``body`` is the raw text between the braces (brace-exclusive).
    """

    path: str
    qualified_name: str
    name: str
    line_start: int
    line_end: int
    body: str


def _find_matching_brace(text: str, open_brace_offset: int) -> int | None:
    """Return the offset of the ``}`` that matches ``text[open_brace_offset]``.

    Handles string / char literals and line/block comments so braces inside
    them do not perturb the depth counter. Returns ``None`` when the file
    is unbalanced (truncated / malformed).
    """
    assert text[open_brace_offset] == "{"

    depth = 1
    i = open_brace_offset + 1
    length = len(text)
    while i < length:
        ch = text[i]
        if ch == "/" and i + 1 < length:
            nxt = text[i + 1]
            if nxt == "/":
                nl = text.find("\n", i + 2)
                i = length if nl == -1 else nl + 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                i = length if end == -1 else end + 2
                continue
        if ch == '"':
            i = _skip_string_literal(text, i, '"')
            continue
        if ch == "'":
            i = _skip_string_literal(text, i, "'")
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _skip_string_literal(text: str, start: int, delim: str) -> int:
    """Walk past a C/C++ string or char literal starting at ``text[start]``.

    Returns the offset of the next character to inspect.
    """
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            i += 2
            continue
        if ch == delim:
            return i + 1
        i += 1
    return len(text)


def extract_functions(path: Path | str) -> list[FunctionDefinition]:
    """Extract C/C++ function definitions from a single source file.

    Returns an empty list for unreadable files; callers can inspect that
    separately from the "zero matches" case by catching ``OSError`` themselves
    if they need to distinguish.
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    results: list[FunctionDefinition] = []
    for match in _FUNCTION_HEAD_RE.finditer(text):
        # The open brace must appear after the arg list; walk forward from
        # the end of the match looking for the first unquoted '{' that opens
        # a body (ignoring default-argument braces).
        search_from = match.end()
        open_offset = _find_body_open_brace(text, search_from)
        if open_offset is None:
            continue
        close_offset = _find_matching_brace(text, open_offset)
        if close_offset is None:
            continue

        qualified = match.group("qualified_name")
        bare = qualified.split("::")[-1]

        line_start = text.count("\n", 0, open_offset) + 1
        line_end = text.count("\n", 0, close_offset) + 1
        body = text[open_offset + 1 : close_offset]

        results.append(
            FunctionDefinition(
                path=str(file_path),
                qualified_name=qualified,
                name=bare,
                line_start=line_start,
                line_end=line_end,
                body=body,
            )
        )

    return results


def _find_body_open_brace(text: str, search_from: int) -> int | None:
    """Walk forward until the brace that opens a function body is found.

    Skips default-argument sub-expressions by tracking parenthesis depth.
    Returns ``None`` if the match turned out to be a declaration only
    (``;`` encountered first) or an unterminated construct.
    """
    paren_depth = 1  # the arg-list ``(`` was consumed by the regex
    i = search_from
    while i < len(text):
        ch = text[i]
        if ch == "/" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "/":
                nl = text.find("\n", i + 2)
                i = len(text) if nl == -1 else nl + 1
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                i = len(text) if end == -1 else end + 2
                continue
        if ch == '"':
            i = _skip_string_literal(text, i, '"')
            continue
        if ch == "'":
            i = _skip_string_literal(text, i, "'")
            continue
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif paren_depth == 0:
            if ch == "{":
                return i
            if ch == ";":
                return None  # pure declaration, no body
        i += 1
    return None
