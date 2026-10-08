"""Unit tests for the public verb-pair matcher."""

from __future__ import annotations

import pytest

from apds_hunt.verb_pairs import (
    PUBLIC_VERB_PAIRS,
    _leading_verb,
    _leading_verb_tokens,
    find_sibling_candidates,
)


class TestTokenization:
    def test_camel_case_splits_on_capital(self):
        assert _leading_verb_tokens("internalSetConfig") == ["internal", "set", "config"]

    def test_snake_case_splits_on_underscore(self):
        assert _leading_verb_tokens("alloc_pages") == ["alloc", "pages"]

    def test_qualified_name_tokenizes_each_camel_hump(self):
        """Our tokenizer splits camelCase even across the ``::`` prefix.

        That is fine for the sibling finder: it strips class qualifiers via
        ``_bare_name`` first, so this behavior does not affect pair matching.
        """
        assert _leading_verb_tokens("SoftVideoDecoder::internalGetConfig") == [
            "soft",
            "video",
            "decoder",
            "internal",
            "get",
            "config",
        ]

    def test_bare_identifier(self):
        assert _leading_verb_tokens("read") == ["read"]

    def test_empty_identifier_returns_empty(self):
        assert _leading_verb_tokens("") == []

    def test_leading_verb_is_first_token_lowercased(self):
        assert _leading_verb("GetConfig") == "get"


class TestSiblingDiscovery:
    """find_sibling_candidates implements the sibling half of the XOR Rule."""

    def test_classic_get_set_pair(self):
        results = find_sibling_candidates(
            "getConfig", ["setConfig", "init", "destroy", "getConfig"]
        )
        assert len(results) == 1
        sibling, pair = results[0]
        assert sibling == "setConfig"
        assert (pair.left, pair.right) == ("get", "set")

    def test_lifecycle_create_destroy(self):
        results = find_sibling_candidates("createBuffer", ["destroyBuffer", "resizeBuffer"])
        assert [name for name, _pair in results] == ["destroyBuffer"]

    def test_memory_alloc_free_snake_case(self):
        results = find_sibling_candidates("alloc_pages", ["free_pages", "map_pages"])
        assert [name for name, _pair in results] == ["free_pages"]

    def test_cve_2024_40658_exact_match(self):
        """The CVE-2024-40658 case: internalGetConfig ↔ internalSetConfig."""
        patched = "SoftVideoDecoderOMXComponent::internalGetConfig"
        candidates = [
            "SoftVideoDecoderOMXComponent::internalSetConfig",
            "SoftVideoDecoderOMXComponent::handleTypeConversion",
            "SoftVideoDecoderOMXComponent::releaseAll",
        ]
        results = find_sibling_candidates(patched, candidates)
        assert len(results) == 1
        sibling, pair = results[0]
        assert sibling == "SoftVideoDecoderOMXComponent::internalSetConfig"
        assert (pair.left, pair.right) == ("get", "set")

    def test_patched_identifier_itself_filtered(self):
        """The patched function itself must never be returned as its own sibling."""
        results = find_sibling_candidates("getConfig", ["getConfig"])
        assert results == []

    def test_candidate_without_matching_tail_rejected(self):
        """get-and-set with a DIFFERENT tail are not siblings (same verb, different base)."""
        results = find_sibling_candidates("getConfig", ["setValue"])
        assert results == []

    def test_unknown_verb_returns_empty(self):
        """A patched function whose leading token is NOT in any pair → empty result."""
        results = find_sibling_candidates("validateMumbleFoo", ["submitMumbleFoo"])
        assert results == []

    def test_overloaded_pair_is_matched_once(self):
        """Even if a candidate matches via two pair entries, it is reported once."""
        results = find_sibling_candidates("getConfig", ["setConfig"])
        assert len(results) == 1

    def test_public_dictionary_has_cve_2024_40658_coverage(self):
        """Regression: the public pairs must include the APDS first-application case."""
        verbs_in_pairs = {(p.left.lower(), p.right.lower()) for p in PUBLIC_VERB_PAIRS}
        assert ("get", "set") in verbs_in_pairs

    @pytest.mark.parametrize(
        "pair_left,pair_right",
        [("create", "destroy"), ("alloc", "free"), ("encode", "decode"), ("lock", "unlock")],
    )
    def test_lifecycle_pairs_present(self, pair_left, pair_right):
        verbs = {(p.left.lower(), p.right.lower()) for p in PUBLIC_VERB_PAIRS}
        assert (pair_left, pair_right) in verbs
