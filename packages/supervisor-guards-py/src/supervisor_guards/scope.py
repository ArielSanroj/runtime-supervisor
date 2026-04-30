"""Scope-guard helpers for chatbot/RAG agents.

The premise: a chatbot's LLM can fabricate entity references (people,
accounts, identifiers) with confident wording, and the user will treat
those as data. The Andrea/Prodesa incident is the canonical case — the
model produced archetype analyses for `Pablo`, `Garbett`, `Lina`,
`Cristina` and `Mercelena`, none of whom were in the user's authorized
team_members list.

This module gives callers a way to:
  - extract candidate entity names from an LLM response (heuristic NER,
    zero deps),
  - check those candidates against an allowed-entities list and surface
    the out-of-scope ones,
  - feed the result into the `scope_guard.base.v1` supervisor policy.

Wiring example::

    from supervisor_guards.scope import assert_entities_in_scope
    from supervisor_guards import supervised

    @supervised("tool_use")
    def respond_to_user(prompt: str, allowed_entities: list[str]) -> str:
        reply = llm.messages.create(...).content[0].text
        check = assert_entities_in_scope(reply, allowed_entities)
        if not check["in_scope"]:
            return f"No tengo datos sobre {', '.join(check['unknown'])}."
        return reply

The helper does NOT call the supervisor itself — it returns a structured
result the caller can use directly OR feed into `payload["entities_mentioned"]`
+ `payload["allowed_entities"]` for the policy engine. We keep the two
layers separate so callers can short-circuit locally without an HTTP
round-trip when they already know the answer.

Design notes:
  - Heuristic NER (capitalization + stopword filter) ships with zero
    dependencies. spaCy/transformers would catch more cases but the
    cost-benefit doesn't pencil out for a one-token-per-message check
    that already runs in the request hot path.
  - Matching is case-insensitive on the Unicode-folded form so
    "ANDREA", "andrea", and "Ándrea" all collapse to the same key.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Literal, TypedDict

# Words that look like proper nouns (capitalized) but aren't entities the
# scope guard cares about. These collide with real names often enough that
# leaving them in produces false positives — every chatbot reply mentioning
# "Resolvedor Estratégico" would otherwise be flagged as "this archetype
# isn't in your team_members". The list is conservative: only spans that
# the chatbot product surface (not the chat content) is producing.
_ENTITY_STOPWORDS_LOWER = frozenset({
    # Days / months / generic time references
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december",
    "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
    "septiembre", "octubre", "noviembre", "diciembre",
    # Common framework / archetype labels in the Clio domain — these are
    # category names, not people. Producto-specific stopwords belong here
    # rather than in the customer's allowed_entities list (which would
    # mix categories with names and corrupt scope checks).
    "strategic", "resolver", "emotional", "processor", "social", "seeker",
    "flexible", "adapter", "avoidant", "cooperative",
    "resolvedor", "estratégico", "estrategico",
    "procesador", "emocional", "buscador", "adaptador",
    "evitativo", "cooperador", "pasivo",
    # Pronouns and determiners that survive title-case (start-of-sentence)
    "the", "this", "that", "these", "those", "some", "any", "all", "each",
    "el", "la", "los", "las", "un", "una", "unos", "unas",
    "este", "esta", "estos", "estas", "ese", "esa", "eso",
    # Modal / hedging words the chatbot uses authoritatively
    "maybe", "perhaps", "however", "therefore", "moreover", "nevertheless",
    "tal", "vez", "quizás", "quizas", "probable", "probablemente",
    # Generic role words ("Manager", "Director" appearing without a name)
    "manager", "director", "lead", "head", "chief", "officer",
    "gerente", "jefe", "líder", "lider",
    # Boilerplate output of the chatbot itself
    "user", "assistant", "system", "company", "team", "equipo",
})

# A name token is a sequence of Unicode letters that starts with an upper-case
# letter. Allows accents (`Ángel`), apostrophes (`O'Brien`), and embedded
# capitals (`McKinsey`) but rejects numbers and punctuation.
_NAME_TOKEN = re.compile(
    r"\b([A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿñÑ’']*"
    r"(?:[ ’'-][A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿñÑ’']*){0,3})\b"
)


class ScopeCheck(TypedDict):
    in_scope: bool
    mentioned: list[str]
    unknown: list[str]
    allowed: list[str]


def _normalize(name: str) -> str:
    """Collapse Unicode + case so that 'Ándrea', 'ANDREA', 'andrea' all
    fold to the same key. NFKC strips combining marks; lower() flattens
    case; .strip() removes possessive markers and stray quotes."""
    folded = unicodedata.normalize("NFKD", name)
    no_marks = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return no_marks.lower().strip(".,;:!?\"'’ ")


def extract_entities(
    text: str,
    *,
    mode: Literal["names", "regex"] = "names",
    pattern: re.Pattern[str] | None = None,
    extra_stopwords: Iterable[str] = (),
) -> list[str]:
    """Pull proper-noun-like spans out of `text`.

    `mode="names"` uses the built-in heuristic: title-cased multi-token
    spans, filtered against a Spanish + English stopword list. Suitable
    for chatbot outputs that mix prose with proper nouns.

    `mode="regex"` accepts a custom `pattern` (must capture group 1) for
    domain-specific identifiers — account numbers, ticket IDs, file
    paths, etc.

    Returns a deduplicated list preserving first-seen order. Spans are
    returned in their original casing so error messages can echo the
    user's name verbatim ("No data on Pablo." not "no data on pablo").
    """
    if mode == "regex":
        if pattern is None:
            raise ValueError("mode='regex' requires a pattern")
        seen: dict[str, str] = {}
        for m in pattern.finditer(text or ""):
            key = m.group(1).strip()
            if key and key not in seen:
                seen[key] = key
        return list(seen.values())

    stopwords = _ENTITY_STOPWORDS_LOWER | {s.lower() for s in extra_stopwords}
    seen_norm: set[str] = set()
    out: list[str] = []
    for m in _NAME_TOKEN.finditer(text or ""):
        span = m.group(1).strip()
        norm = _normalize(span)
        if not norm:
            continue
        # Reject all-stopword spans (every token is in the stopword list).
        # A multi-word span that includes ONE real name is kept — e.g.
        # "Manager Andrea" produces "Manager Andrea" because at least one
        # token survives the filter. We don't try to split here; over-
        # reporting "Manager Andrea" is safer than dropping "Andrea".
        tokens = re.split(r"[\s\-’']+", norm)
        if all(t in stopwords for t in tokens if t):
            continue
        if norm in seen_norm:
            continue
        seen_norm.add(norm)
        out.append(span)
    return out


def assert_entities_in_scope(
    text: str,
    allowed: Iterable[str],
    *,
    extractor=extract_entities,
) -> ScopeCheck:
    """Compare entities mentioned in `text` against `allowed`.

    Returns a `ScopeCheck` dict:
      - `in_scope`: True iff every mentioned entity is in the allowed set.
      - `mentioned`: extracted entities (in original casing).
      - `unknown`: subset of `mentioned` that didn't match `allowed`.
      - `allowed`: the normalized allowed list (for caller debugging).

    Matching is case- and accent-insensitive (`_normalize`). A mention of
    "ANDREA PRIETO" matches an allowed value of "Andrea Prieto"; a
    mention of "Andrea P." matches "Andrea P." but NOT "Andrea Prieto"
    (we don't do prefix matching — the caller controls the granularity
    of `allowed`).

    Empty `text` → `in_scope=True` (nothing to check).
    Empty `allowed` + non-empty `mentioned` → `in_scope=False, unknown=mentioned`.
    The supervisor policy `scope_guard.base.v1` handles the "scope not
    passed" case at `review` action; this helper just reports the math.
    """
    mentioned = extractor(text or "")
    allowed_list = list(allowed or [])
    allowed_norm = {_normalize(a) for a in allowed_list}
    unknown = [m for m in mentioned if _normalize(m) not in allowed_norm]
    return ScopeCheck(
        in_scope=not unknown,
        mentioned=mentioned,
        unknown=unknown,
        allowed=allowed_list,
    )


__all__ = ["ScopeCheck", "extract_entities", "assert_entities_in_scope"]
