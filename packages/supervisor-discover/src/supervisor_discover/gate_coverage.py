"""Detect call-sites that are already wrapped by @supervised / guarded(...).

Scanners report risky call-sites independent of whether they're gated. If the
user has already wrapped a function with @supervised or routed a call through
guarded(action, payload, fn, ...), the finding inside that function is no
longer actionable as "do this now" — it's already done. Without this post-pass,
the scanner gaslights the user on every re-scan ("wrap stripe" → "I already
did that on PR #142").

This module runs ONCE per scan (after all scanners finish) and mutates each
finding's `extra` dict to add:
    - "already_gated": True/False
    - "gated_by": short label of how (`@supervised`, `guarded(...)`, …)

The detection is intentionally conservative — false positives here cause us
to UNDER-report wrap recommendations (annoying but recoverable). False
negatives cause us to OVER-report ("wrap this thing you already wrapped"),
which is what we're trying to fix in the first place.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from .findings import Finding
from .scanners._utils import dotted_name, parse_python, safe_read

# Names that, when seen as a decorator or as a call, mark the surrounding
# function body as already gated. Both bare and dotted forms count
# (`@supervised`, `@guards.supervised`, `runtime_supervisor.supervised`).
_GATE_DECORATOR_NAMES = frozenset({"supervised", "supervise"})

# Names that, when called positionally with a function reference as one of
# the early args, gate the function being wrapped indirectly:
#     guarded("payment", payload, _do_stripe_checkout, *call_args)
#     supervised("tool_use", do_thing, *args)         # decorator-less form
#     run_supervised("data_access", fn, ...)
_GATE_CALLABLE_NAMES = frozenset({
    "guarded", "supervised", "supervise",
    "run_supervised", "with_supervisor", "with_guard",
})


def _decorator_name(dec: ast.expr) -> str | None:
    """Resolve the name of a decorator node (`@foo`, `@foo.bar`, `@foo(...)`).

    For decorator factories (`@supervised("tool_use")`), the AST is `ast.Call`
    whose `func` is the actual name; for plain decorators (`@supervised`) it's
    `ast.Name` directly. Returns the rightmost dotted segment.
    """
    if isinstance(dec, ast.Call):
        dec = dec.func
    name = dotted_name(dec)
    if name is None:
        return None
    return name.rsplit(".", 1)[-1]


def _callable_short_name(node: ast.expr) -> str | None:
    """Last segment of a dotted call target. `guards.supervised` → `supervised`.
    Returns None for non-name expressions (subscripts, lambdas, ...)."""
    name = dotted_name(node)
    if name is None:
        return None
    return name.rsplit(".", 1)[-1]


def _functions_by_name(tree: ast.Module) -> dict[str, list[tuple[int, int]]]:
    """Map function name → list of (start_line, end_line). Multiple entries
    when a name is reused (overrides or nested defs)."""
    out: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            out[node.name].append((node.lineno, end))
    return out


def _gated_ranges_in_module(tree: ast.Module) -> list[tuple[int, int, str]]:
    """Return [(start_line, end_line, label)] for every gated function body.

    Three patterns count as gated:
      1. `@supervised(...)` decorator on a def — the body of the def is gated.
      2. A call to `guarded(action, payload, fn, ...)` — the function `fn`
         (resolved by name in the same module) is gated.
      3. A call to `supervised(action, fn, ...)` (no decorator form) — same.
    """
    ranges: list[tuple[int, int, str]] = []
    funcs_by_name = _functions_by_name(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            for dec in node.decorator_list:
                name = _decorator_name(dec)
                if name in _GATE_DECORATOR_NAMES:
                    ranges.append((node.lineno, end, f"@{name}"))
                    break

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _callable_short_name(node.func)
        if callee not in _GATE_CALLABLE_NAMES:
            continue
        # Look at ALL positional args, not just the first ast.Name. The
        # supervincent pattern `guarded("payment", payload, _do_stripe_checkout,
        # body, price_id)` puts the payload dict-var BEFORE the function
        # reference — bailing on the first ast.Name would miss the actual
        # wrap target. We treat any ast.Name whose id resolves to a function
        # in this module as the gated callable.
        for arg in node.args:
            if not isinstance(arg, ast.Name):
                continue
            target_name = arg.id
            for start, end in funcs_by_name.get(target_name, []):
                ranges.append((start, end, f"{callee}(...)"))
        # Also accept keyword-style: `guarded(action=..., fn=do_thing)`.
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                target_name = kw.value.id
                for start, end in funcs_by_name.get(target_name, []):
                    ranges.append((start, end, f"{callee}(...)"))

    return ranges


def _gated_ranges_for_file(path: Path) -> list[tuple[int, int, str]]:
    """Return gated line ranges for a single Python file. Empty list on parse
    failure or unreadable file — gating is opportunistic."""
    if path.suffix not in (".py", ".ipynb"):
        return []
    text = safe_read(path)
    if text is None:
        return []
    tree = parse_python(text)
    if tree is None:
        return []
    return _gated_ranges_in_module(tree)


def _line_inside_any(line: int, ranges: list[tuple[int, int, str]]) -> str | None:
    """If `line` is inside one of `ranges`, return the gate label; else None."""
    for start, end, label in ranges:
        if start <= line <= end:
            return label
    return None


def annotate_findings(findings: list[Finding]) -> list[Finding]:
    """Mark findings whose line lies inside an already-gated function body.

    Mutates each finding's `.extra` dict in place; also returns the list so
    callers can chain. Findings on TS/JS files or unparseable Python files
    pass through unchanged. Idempotent — calling twice is safe.
    """
    cache: dict[str, list[tuple[int, int, str]]] = {}
    for f in findings:
        if (f.extra or {}).get("already_gated") is not None:
            # Already annotated (idempotent). Skip the file work.
            continue
        path_str = f.file
        if path_str not in cache:
            cache[path_str] = _gated_ranges_for_file(Path(path_str))
        ranges = cache[path_str]
        if not ranges:
            f.extra = {**(f.extra or {}), "already_gated": False}
            continue
        label = _line_inside_any(f.line, ranges)
        if label is None:
            f.extra = {**(f.extra or {}), "already_gated": False}
        else:
            f.extra = {
                **(f.extra or {}),
                "already_gated": True,
                "gated_by": label,
            }
    return findings


def already_gated(finding: Finding) -> bool:
    """Convenience predicate for renderers."""
    return bool((finding.extra or {}).get("already_gated"))
