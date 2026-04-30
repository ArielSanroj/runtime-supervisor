"""Unit tests for the scope guard helper.

The Andrea/Prodesa incident (cliocsbot, 2026-04-29) is the regression
target: an LLM produced "Pablo es un Strategic Resolver porque..." with
authoritative tone, where Pablo wasn't in the user's `team_members`. The
manager treated the response as data. These tests pin the matching rules
that prevent the same shape from passing through.
"""
from __future__ import annotations

import re

import pytest

from supervisor_guards.scope import (
    assert_entities_in_scope,
    extract_entities,
)


# ── extract_entities ─────────────────────────────────────────────────


def test_extracts_capitalized_proper_nouns():
    out = extract_entities("Andrea Prieto y Karen son del equipo de Gestión Humana.")
    assert "Andrea Prieto" in out
    assert "Karen" in out


def test_filters_archetype_labels():
    """The Clio domain emits 'Strategic Resolver', 'Emotional Processor'
    etc. as category names — they look like proper nouns to a naive
    matcher but they're labels, not people. Pinning the stopword list."""
    out = extract_entities(
        "Andrea es Strategic Resolver y Karen es Emotional Processor."
    )
    assert out == ["Andrea", "Karen"]
    assert "Strategic Resolver" not in out
    assert "Emotional Processor" not in out


def test_filters_days_months_in_two_languages():
    out = extract_entities("On Monday, Andrea will meet with Karen. El Lunes también Pablo.")
    assert "Monday" not in out
    assert "Lunes" not in out
    assert "Andrea" in out
    assert "Karen" in out
    assert "Pablo" in out


def test_handles_accents_via_normalization():
    """`Ángel` and `ANGEL` should both fold to the same key — the test
    here is on `assert_entities_in_scope` matching, since the extractor
    preserves original casing."""
    extracted = extract_entities("Ángel González lidera el equipo de Bogotá.")
    assert "Ángel González" in extracted
    # The 'Bogotá' span is captured but it's a city — the caller's
    # `allowed_entities` filters this. We don't strip city names from
    # the extractor because doing so well requires a gazetteer; better
    # to over-report and let the policy handle it.


def test_dedupes_repeated_mentions():
    out = extract_entities("Andrea dijo. Andrea pidió. Andrea volvió.")
    assert out == ["Andrea"]


def test_no_capitals_returns_empty():
    out = extract_entities("hola, todo bien por acá, gracias.")
    assert out == []


def test_empty_input_returns_empty():
    assert extract_entities("") == []
    assert extract_entities(None) == []  # type: ignore[arg-type]


def test_regex_mode_for_account_ids():
    """Domain-specific identifier extraction — the caller can pass any
    pattern with one capture group. Useful for ticket IDs, account
    numbers, file paths, etc."""
    pattern = re.compile(r"\b(ACC-\d{6})\b")
    out = extract_entities(
        "Move funds from ACC-123456 to ACC-654321 today.",
        mode="regex",
        pattern=pattern,
    )
    assert out == ["ACC-123456", "ACC-654321"]


def test_regex_mode_requires_pattern():
    with pytest.raises(ValueError, match="requires a pattern"):
        extract_entities("anything", mode="regex")


def test_extra_stopwords_filter_through():
    out = extract_entities(
        "ProjectAlpha is leading the migration. Andrea will follow up.",
        extra_stopwords={"projectalpha"},
    )
    assert "ProjectAlpha" not in out
    assert "Andrea" in out


# ── assert_entities_in_scope ─────────────────────────────────────────


def test_in_scope_when_all_entities_authorized():
    text = "Andrea y Karen están al día con sus reportes."
    allowed = ["Andrea Prieto", "Andrea", "Karen", "Laura"]
    result = assert_entities_in_scope(text, allowed)
    assert result["in_scope"] is True
    assert result["unknown"] == []


def test_andrea_pablo_regression_blocks_unknown_name():
    """The literal Andrea/Prodesa scenario: the model invents 'Pablo'
    inside an authorized response. Must flag Pablo as unknown."""
    text = (
        "Andrea es Strategic Resolver. Pablo, según sus respuestas, "
        "puede ser un Resolutivo Dominante."
    )
    allowed = ["Andrea Prieto", "Andrea", "Karen", "Laura", "Geraldine"]
    result = assert_entities_in_scope(text, allowed)
    assert result["in_scope"] is False
    assert "Pablo" in result["unknown"]
    assert "Andrea" not in result["unknown"]


def test_case_and_accent_folding_matches():
    """`ANDREA` in the LLM output and `Andrea Prieto` in the allowed
    list must match so the helper doesn't fire on cosmetic case
    differences."""
    text = "ANDREA confirmó la reunión."
    allowed = ["Andrea"]
    result = assert_entities_in_scope(text, allowed)
    assert result["in_scope"] is True


def test_empty_allowed_with_mentions_is_out_of_scope():
    """An empty allowed list against a non-empty mentioned list flags
    everything. The supervisor policy `scope_guard.base.v1` has a
    `review`-level rule for this case (likely a wiring bug); this
    helper just returns the math."""
    text = "Andrea is on leave."
    result = assert_entities_in_scope(text, [])
    assert result["in_scope"] is False
    assert result["unknown"] == ["Andrea"]


def test_empty_text_is_in_scope():
    result = assert_entities_in_scope("", ["Andrea"])
    assert result["in_scope"] is True
    assert result["mentioned"] == []


def test_returns_original_casing_for_user_facing_messages():
    """When the helper is used to compose a fallback like 'No tengo datos
    sobre X', the X must echo the user's casing for readability."""
    text = "Pablo Pérez está activo en su nuevo rol."
    allowed = ["Andrea"]
    result = assert_entities_in_scope(text, allowed)
    assert "Pablo Pérez" in result["unknown"]


def test_allowed_subset_of_mentioned_marks_only_unknown():
    """Mentions that match a SUBSET of allowed must not flag the matches
    as unknown — only the genuinely-out-of-scope ones."""
    text = "Andrea pasó por Pablo y por Laura."
    allowed = ["Andrea", "Laura"]
    result = assert_entities_in_scope(text, allowed)
    assert result["in_scope"] is False
    assert result["unknown"] == ["Pablo"]
