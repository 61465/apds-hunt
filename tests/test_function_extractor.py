"""Unit tests for the C/C++ function extractor."""

from __future__ import annotations

from pathlib import Path

from apds_hunt.function_extractor import extract_functions


def _write(tmp_path: Path, name: str, body: str) -> Path:
    f = tmp_path / name
    f.write_text(body, encoding="utf-8")
    return f


class TestFunctionExtractor:
    def test_single_function_detected(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "a.cpp",
            "int add(int x, int y) {\n    return x + y;\n}\n",
        )
        defs = extract_functions(src)
        assert len(defs) == 1
        assert defs[0].name == "add"
        assert defs[0].qualified_name == "add"
        assert defs[0].line_start == 1
        assert defs[0].line_end == 3

    def test_member_function_qualified(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "b.cpp",
            "void SoftDecoder::internalSetConfig(int idx) {\n    doThing(idx);\n}\n",
        )
        defs = extract_functions(src)
        assert len(defs) == 1
        assert defs[0].name == "internalSetConfig"
        assert defs[0].qualified_name == "SoftDecoder::internalSetConfig"

    def test_declaration_only_is_not_extracted(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "c.cpp",
            "int only_declared(int x);\n\nint real_definition(int x) {\n    return x;\n}\n",
        )
        defs = extract_functions(src)
        assert [d.name for d in defs] == ["real_definition"]

    def test_nested_braces_in_body_balanced(self, tmp_path: Path):
        """Inner-block braces must not confuse the matcher."""
        src = _write(
            tmp_path,
            "d.cpp",
            (
                "int outer(int x) {\n"
                "    if (x > 0) {\n"
                "        for (int i = 0; i < x; ++i) {\n"
                "            doWork(i);\n"
                "        }\n"
                "    }\n"
                "    return 0;\n"
                "}\n"
            ),
        )
        defs = extract_functions(src)
        assert len(defs) == 1
        assert defs[0].line_start == 1
        assert defs[0].line_end == 8

    def test_two_functions_detected_independently(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "e.cpp",
            (
                "int first(int x) { return x; }\n"
                "int second(int x) { return x + 1; }\n"
            ),
        )
        defs = extract_functions(src)
        names = sorted(d.name for d in defs)
        assert names == ["first", "second"]

    def test_brace_inside_string_literal_ignored(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "f.cpp",
            'const char* msg(int x) {\n    const char* s = "{not a block}";\n    return s;\n}\n',
        )
        defs = extract_functions(src)
        assert len(defs) == 1
        assert defs[0].name == "msg"

    def test_brace_inside_line_comment_ignored(self, tmp_path: Path):
        src = _write(
            tmp_path,
            "g.cpp",
            "void note() {\n    // trailing } does nothing\n}\n",
        )
        defs = extract_functions(src)
        assert len(defs) == 1
        assert defs[0].name == "note"

    def test_unreadable_file_returns_empty(self, tmp_path: Path):
        bogus = tmp_path / "does-not-exist.cpp"
        assert extract_functions(bogus) == []
