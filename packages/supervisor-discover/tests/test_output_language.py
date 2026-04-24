"""Product-voice compliance tests for scanner output.

Guardrails against a pentest-report voice creeping back into user-facing
strings. See `packages/supervisor-discover/VOICE.md` for the full spec;
these tests enforce the two easiest-to-regress rules:

1. No OWASP / CVSS / compliance / governance jargon as the **headline** of
   a finding (the first sentence of `rationale`). Footnotes are fine;
   titles are not.

2. Every rationale references at least one **action verb** from the
   allow-list — `gate / block / wrap / run / execute / send / create /
   call / delete / overwrite / exfil / inject / break / touch / move /
   leak / spawn / drain / …`. Keeps rationales concrete instead of
   drifting into abstract "X detected" language.

Runs the scanner against the Flask + adversarial-trap fixtures. If a new
detector emits a rationale that violates either rule, the test fails with
the offending text + which rule it broke.
"""
from __future__ import annotations

import re
from pathlib import Path

from supervisor_discover.scanners import scan_all

_FIXTURES = [
    Path(__file__).parent / "fixtures/fake_flask_app",
    Path(__file__).parent / "fixtures/fake_next_app",
    Path(__file__).parent / "fixtures/adversarial_trap",
]

# Phrases that MUST NOT appear in a rationale's headline (first sentence).
# Case-insensitive match. Footnotes / later sentences can still reference
# these, but never as the opening line.
_BANNED_IN_HEADLINE = [
    "owasp",
    "cvss",
    "compliance violation",
    "governance",
    "policy engine",
    "threat pipeline",
    "risk scoring",
    "auditability",
    # OWASP LLM category identifiers (LLM01 through LLM10).
    "llm0",
    "llm10",
]

# Action vocabulary — at least one must appear anywhere in the rationale.
# Deliberately generous: matches both the imperatives and the noun forms
# that show up in concrete Problem statements ("can send", "sends email").
_ACTION_VERBS = [
    "gate", "gating",
    "block", "blocks", "blocking",
    "wrap", "wraps", "wrapping",
    "catch", "catches",
    "run", "runs", "running",
    "execute", "executes",
    "send", "sends", "sending",
    "create", "creates",
    "call", "calls",
    "delete", "deletes", "deleting",
    "overwrite", "overwrites",
    "exfil",
    "inject", "injects", "injection",
    "break", "breaks", "broken",
    "touch", "touches",
    "move", "moves", "moving",
    "leak", "leaks", "leaking",
    "spawn", "spawns",
    "drain", "drains",
    "compromise", "compromises",
    "escalate", "escalates",
    "impersonate", "impersonation",
    "mutate", "mutates", "mutation",
    "expose", "exposes",
    "spam", "spams",
    "burn", "burns",
    "abuse",
    # Passive-voice matchers — "can be X'd" phrasing is common in rationales.
    "can be",
]


def _collect_rationales() -> list[tuple[str, str, str]]:
    """Return `(scanner, file_tail, rationale)` for every finding across
    all fixtures. Dedup by (scanner, rationale) so identical strings from
    multiple hits only get tested once."""
    seen: dict[tuple[str, str], tuple[str, str, str]] = {}
    for fixture in _FIXTURES:
        for f in scan_all(fixture):
            key = (f.scanner, f.rationale)
            if key in seen:
                continue
            file_tail = Path(f.file).name
            seen[key] = (f.scanner, file_tail, f.rationale)
    return list(seen.values())


def _first_sentence(text: str) -> str:
    """Everything up to the first period / em-dash / newline — the part a
    reader sees as the 'headline'. If there's no terminator, return the
    whole thing."""
    m = re.search(r"[.\n—]", text)
    return text[: m.start()] if m else text


def test_rationale_headline_has_no_pentest_jargon() -> None:
    """Golden rule: scanner output sounds like a senior engineer helping
    a vibe-coder ship — not a compliance report. Reject banned phrases in
    the headline (first sentence)."""
    offenders: list[str] = []
    for scanner, file_tail, rationale in _collect_rationales():
        headline = _first_sentence(rationale).lower()
        for banned in _BANNED_IN_HEADLINE:
            if banned in headline:
                offenders.append(
                    f"  [{scanner}] {file_tail}\n"
                    f"    banned phrase: {banned!r}\n"
                    f"    headline:      {_first_sentence(rationale)!r}"
                )
                break
    assert not offenders, (
        "Pentest-report voice slipped into a rationale headline. "
        "Read packages/supervisor-discover/VOICE.md and rewrite:\n\n"
        + "\n\n".join(offenders)
    )


def test_rationale_uses_action_vocabulary() -> None:
    """Concrete voice check: every rationale must reference at least one
    action verb from the allow-list. Catches drift into abstract
    'X detected' language with no real-world scenario attached."""
    offenders: list[str] = []
    for scanner, file_tail, rationale in _collect_rationales():
        lowered = rationale.lower()
        if not any(verb in lowered for verb in _ACTION_VERBS):
            offenders.append(
                f"  [{scanner}] {file_tail}\n"
                f"    no action verb in: {rationale[:140]!r}"
            )
    assert not offenders, (
        "A rationale drifted into abstract voice — no concrete action verb "
        "found. VOICE.md rule #4: problem statements are real-world "
        "scenarios, not API names. Fix:\n\n"
        + "\n\n".join(offenders)
    )
