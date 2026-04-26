"""Build pre-populated allowlists from real findings.

The combo policies (`tool_use.llm-plus-shell-exec.v1.yaml`,
`tool_use.mass-email-plus-customer-db.v1.yaml`, fs-write/delete combos) ship
with placeholder symbols like `ALLOWED_COMMANDS` that the user has to define
by hand. That's a fork of the repo's reality — the commands are already in
the source, the scanner saw them, and we still made the user re-type them.

This module reads the finding stream and emits the real values:

  - `extract_shell_command_allowlist(findings)` →
        [["python", "-m", "pip", "install", "-r", "requirements.txt"],
         ["git", "init"],
         ["pytest"]]
    pulled from `extra["argv"]` on fs-shell shell-exec findings.

  - `extract_fs_path_prefixes(findings)` → ordered set of directories the
    repo writes/deletes to with literal paths (e.g. `/tmp`, `data/`,
    `logs/`). Useful for fs-write / fs-delete allowlists.

The output is sorted and deduped so re-scans produce stable diffs even when
findings reorder.
"""
from __future__ import annotations

import os
from typing import Iterable

from .findings import Finding


def _is_shell_exec_with_argv(f: Finding) -> bool:
    extra = f.extra or {}
    return (
        f.scanner == "fs-shell"
        and extra.get("family") == "shell-exec"
        and isinstance(extra.get("argv"), list)
        and bool(extra["argv"])
    )


def extract_shell_command_allowlist(findings: Iterable[Finding]) -> list[list[str]]:
    """Return deduped argvs for shell-exec call-sites that had literal args.

    Each item is a list of strings (the actual command + its args), sorted
    deterministically so policy YAMLs don't drift between scans. Items are
    deduped on `(cmd, *args)` — if the same call appears in 12 places the
    allowlist still has one entry.

    Empty list when no shell-exec finding had a literal argv (every call
    used variables) — caller should keep the placeholder behavior in that
    case.
    """
    seen: set[tuple[str, ...]] = set()
    out: list[list[str]] = []
    for f in findings:
        if not _is_shell_exec_with_argv(f):
            continue
        argv = [str(x) for x in (f.extra or {}).get("argv", [])]
        if not argv:
            continue
        key = tuple(argv)
        if key in seen:
            continue
        seen.add(key)
        out.append(argv)
    out.sort()
    return out


def extract_fs_path_prefixes(findings: Iterable[Finding]) -> list[str]:
    """Best-effort list of directory prefixes the repo writes/deletes to.

    Walks fs-write / fs-delete findings whose snippet contains a literal
    quoted path (we don't carry the path on `extra` today, so this is a
    cheap approximation that hits common cases like `Path("/tmp/...")` /
    `os.unlink("/var/log/foo")`). Items are deduped to the directory
    component and sorted.

    This is intentionally conservative: when the path is a variable or an
    f-string with substitutions we skip the finding rather than guess.
    """
    seen: set[str] = set()
    out: list[str] = []
    for f in findings:
        family = (f.extra or {}).get("family")
        if f.scanner != "fs-shell" or family not in {"fs-delete", "fs-write"}:
            continue
        # Snippet shape: `os.unlink("/tmp/x")` / `Path("/data").unlink()`.
        # Pull the first quoted string. Skip if there's an f-string brace.
        snippet = f.snippet or ""
        if "{" in snippet:  # f-string interpolation — too dynamic to trust
            continue
        path = _first_quoted_string(snippet)
        if path is None:
            continue
        # Dir component — strip the filename so the allowlist doesn't include
        # one entry per logfile. `/tmp/sessions/abc.json` → `/tmp/sessions`.
        directory = os.path.dirname(path) or path
        if directory in seen:
            continue
        seen.add(directory)
        out.append(directory)
    out.sort()
    return out


def _first_quoted_string(snippet: str) -> str | None:
    """Return the first single- or double-quoted string in `snippet`,
    minus the quotes. None if no plain string literal is present."""
    for quote in ("'", '"'):
        if quote not in snippet:
            continue
        start = snippet.index(quote)
        end = snippet.find(quote, start + 1)
        if end == -1:
            continue
        candidate = snippet[start + 1 : end]
        # Skip empty strings and strings that look like format placeholders.
        if not candidate or "{" in candidate:
            continue
        return candidate
    return None
