"""Read `<repo>/.supervisor-ignore` and annotate findings the dev wants
silenced.

Without this, every re-scan re-lists the same findings the dev already
reviewed and decided don't apply. After a few scans the dev stops reading
the report — the noise drowns out the new signal. The reviewer specifically
called this out on supervincent and castor-1: build-script subprocess calls
and tempfile-controlled paths kept showing up despite explicit verification.

The file format is gitignore-shaped (one rule per line, `#` for comments)
with a fixed column structure that's still readable in plain text:

    # path[:line]                    reason                 [reviewer]   [date]
    backend/setup.py:58              build-script-not-prod  arielsanroj  2026-04-26
    backend/app/routes/clean.py:42   tempfile-path
    scripts/**                       build-only

Match logic, in order:
  1. Exact `path:line` rules win first.
  2. Exact `path` (no line) rules match every finding in that file.
  3. Glob rules (`*` / `**`) match by `fnmatch` semantics on the relative path.

Findings that match get `extra["suppressed"] = True` plus the rule's reason
and reviewer. The renderer routes them out of the priority list and into
a separate "Suppressed" section so re-scans show only what's new or
broken-suppressions (the rule no longer matches anything — likely the call
moved or was deleted).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .findings import Finding


_IGNORE_FILENAME = ".supervisor-ignore"


@dataclass(frozen=True)
class SuppressionRule:
    """One line from `.supervisor-ignore`."""
    raw: str            # original line — for error messages and the rendered table
    pattern: str        # the path pattern, e.g. "backend/setup.py" or "scripts/**"
    line: int | None    # explicit line number when present, else None
    reason: str         # short token, never empty (parser rejects rules without one)
    reviewer: str       # optional, "" when not provided
    date: str           # optional, "" when not provided


@dataclass(frozen=True)
class SuppressionMatch:
    """One finding suppressed by one rule. Used by the renderer to show what
    was hidden and why."""
    finding: Finding
    rule: SuppressionRule


def _parse_line(raw: str) -> SuppressionRule | None:
    """Return a `SuppressionRule` from `raw` or `None` for empty / comment.

    A line with no reason is an error — return None (caller will warn). The
    parser is whitespace-tolerant: any run of spaces or tabs separates the
    columns, and the reason can't contain whitespace.
    """
    text = raw.strip()
    if not text or text.startswith("#"):
        return None
    parts = text.split()
    if len(parts) < 2:
        return None
    pattern_field = parts[0]
    reason = parts[1]
    reviewer = parts[2] if len(parts) > 2 else ""
    date = parts[3] if len(parts) > 3 else ""

    line: int | None = None
    if ":" in pattern_field:
        # `path:42` or `path:*`. Numeric line wins; `*` means "any line"
        # (same as omitting the colon).
        path, _, suffix = pattern_field.rpartition(":")
        suffix = suffix.strip()
        if suffix.isdigit():
            line = int(suffix)
            pattern = path
        elif suffix == "*":
            pattern = path
        else:
            # Looks like a Windows-style path (e.g. C:\…). Treat the whole
            # field as the pattern.
            pattern = pattern_field
    else:
        pattern = pattern_field

    return SuppressionRule(
        raw=text, pattern=pattern, line=line,
        reason=reason, reviewer=reviewer, date=date,
    )


def load_rules(repo_root: Path) -> list[SuppressionRule]:
    """Read `.supervisor-ignore` from `repo_root` if it exists. Returns an
    empty list when the file is absent (the common case)."""
    ignore_path = repo_root / _IGNORE_FILENAME
    if not ignore_path.is_file():
        return []
    try:
        text = ignore_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out: list[SuppressionRule] = []
    for raw in text.splitlines():
        rule = _parse_line(raw)
        if rule is not None:
            out.append(rule)
    return out


def _to_relative(file: str, repo_root: Path) -> str:
    """Best-effort relative path. Findings carry absolute paths; ignore rules
    are written relative to repo root. Falls back to the raw path when the
    finding lives outside the root (shouldn't happen, but be defensive)."""
    try:
        return str(Path(file).resolve().relative_to(repo_root.resolve()))
    except (OSError, ValueError):
        return file


def _matches(rule: SuppressionRule, rel_path: str, line: int) -> bool:
    """True when `rule` covers a finding at (rel_path, line).

    - `path:42` matches only line 42.
    - `path` (no line) matches every line in that file.
    - Globs work the same way; line constraint applies to the file match.
    """
    if rule.line is not None and rule.line != line:
        return False
    if "*" in rule.pattern or "?" in rule.pattern or "[" in rule.pattern:
        return fnmatch.fnmatch(rel_path, rule.pattern)
    # Exact match on full path or any directory prefix.
    return rel_path == rule.pattern or rel_path.startswith(rule.pattern + "/")


def annotate_findings(
    findings: list[Finding],
    rules: list[SuppressionRule],
    repo_root: Path,
) -> list[SuppressionMatch]:
    """Mutate `findings` to flag suppressed ones; return the matches.

    Each suppressed finding gets:
      - `extra["suppressed"] = True`
      - `extra["suppression_reason"]` — the rule's reason token
      - `extra["suppressed_by"]` — the rule's raw line for traceability

    The function is idempotent — calling it twice with the same rules leaves
    the same annotations. Findings on absolute paths outside `repo_root`
    pass through unchanged (defensive — shouldn't happen during a normal
    scan, but the helper is reused by the diff command which can mix repos).
    """
    if not rules:
        return []
    matches: list[SuppressionMatch] = []
    for f in findings:
        if (f.extra or {}).get("suppressed"):
            # Already annotated — skip without disturbing the prior match.
            continue
        rel = _to_relative(f.file, repo_root)
        for rule in rules:
            if not _matches(rule, rel, f.line):
                continue
            f.extra = {
                **(f.extra or {}),
                "suppressed": True,
                "suppression_reason": rule.reason,
                "suppressed_by": rule.raw,
            }
            matches.append(SuppressionMatch(finding=f, rule=rule))
            break  # first match wins
    return matches


def is_suppressed(finding: Finding) -> bool:
    """Convenience predicate for renderers."""
    return bool((finding.extra or {}).get("suppressed"))


def stale_rules(rules: list[SuppressionRule], matches: Iterable[SuppressionMatch]) -> list[SuppressionRule]:
    """Return rules that didn't match any finding. The renderer can warn the
    dev: a rule that no longer matches probably means the call-site moved or
    was deleted, and the suppression is hiding a different reality now.
    """
    matched_rules = {m.rule.raw for m in matches}
    return [r for r in rules if r.raw not in matched_rules]
