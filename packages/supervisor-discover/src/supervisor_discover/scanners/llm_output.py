"""Detect LLM responses flowing to a user-facing sink without validation.

Pairs with the `llm-calls` scanner: that one finds the call, this one
finds the *path from the call to the user* without an intermediate
scope/identity check. The Andrea/Prodesa class — model invents a name,
user trusts it as data — is the regression target.

Confidence:
  - `high`: source and sink in the same FunctionDef, no sanitizer in
    between. Public output.
  - `medium`: cross-function or other heuristic-resolved cases. Behind
    the paywall in the public scan, surfaced in FULL_REPORT.

What the scanner does NOT do (deferred to v2):
  - JS/TS support (regex prototype possible; Python AST is the v1
    investment).
  - Cross-module taint.
  - Loop-aware tracking.

Dependent on the `_taint` helper in this package; the helper carries
the source/sink/sanitizer config so the lists stay co-located.
"""
from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from ._imports import build_alias_map
from ._taint import LLM_SOURCE_ROOTS, find_taint
from ._utils import parse_python, python_files, safe_read


_RATIONALE = (
    "The LLM output flows to the user without passing through a "
    "validation step. If the model invents a name, fact, or "
    "identifier, the user sees the assertion as data. Add an "
    "`assert_entities_in_scope(reply, allowed)` (or similar "
    "source-of-truth check) between the LLM call and the response."
)


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        # Quick reject: if the file imports nothing from an LLM SDK,
        # taint can't originate here. The visitor would arrive at the
        # same conclusion, but bailing early keeps the scanner fast on
        # large repos.
        if not any(s in text for s in ("openai", "anthropic", "langchain", "llama_index")):
            continue
        tree = parse_python(text)
        if tree is None:
            continue
        aliases = build_alias_map(tree)
        # Second-stage reject: the alias map must contain at least one
        # LLM-rooted import. Catches files that mention "openai" in a
        # comment or string but don't actually import it.
        if not any(
            v.split(".")[0] in LLM_SOURCE_ROOTS for v in aliases.values()
        ):
            continue
        for tf in find_taint(tree, aliases=aliases, file=str(path)):
            findings.append(Finding(
                scanner="llm-output",
                file=tf.file,
                line=tf.line,
                snippet=tf.snippet,
                suggested_action_type="tool_use",
                confidence=tf.confidence,
                rationale=_RATIONALE,
                extra={
                    "family": "llm-output-without-validation",
                    "func": tf.func_name,
                    "source_line": tf.source_line,
                    "sink_kind": tf.sink_kind,
                },
            ))
    return findings
