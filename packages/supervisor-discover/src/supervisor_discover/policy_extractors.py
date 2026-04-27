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

  - `extract_action_enums(root)` → `{EnumName: [member_value, ...]}`
    for action-shaped enum classes the repo defines (e.g. castor-1's
    `class AgentAction(str, Enum): CREATE_INCIDENT = "create_incident"`).
    Used to emit a `tool_use.<repo>.v1.yaml` policy pre-populated with the
    repo's actual action vocabulary instead of generic `'system.exec'`-style
    placeholders.

The output is sorted and deduped so re-scans produce stable diffs even when
findings reorder.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Iterable

from .findings import Finding
from .scanners._utils import parse_python, python_files, safe_read


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


# ─── Action-enum extraction ────────────────────────────────────────


# Class-name suffixes that indicate "this enum lists the actions an
# agent can take". Bias toward narrow matching: false positives here
# pollute the generated policy with non-action values (StatusEnum
# members appearing in an `allowed_actions` list), so we exclude
# generic state/status/type enums by default.
_ACTION_ENUM_SUFFIXES = (
    "Action", "Actions",
    "Tool", "Tools", "ToolName", "ToolKind",
    "Intent", "Intents",
    "Command", "Commands",
    "Operation", "Operations",
    "Verb", "Verbs",
)
_NON_ACTION_TOKENS = (
    "status", "state", "phase", "level", "priority",
    "severity", "mode", "type", "kind",
)


def _is_action_enum_name(name: str) -> bool:
    if not any(name.endswith(suf) for suf in _ACTION_ENUM_SUFFIXES):
        return False
    lower = name.lower()
    return not any(tok in lower for tok in _NON_ACTION_TOKENS)


def _is_enum_subclass(node: ast.ClassDef) -> bool:
    """True when any base looks like an `Enum` class. Recognizes:
      - `Enum`, `IntEnum`, `StrEnum`, `Flag`, `IntFlag` (bare names)
      - `enum.Enum`, etc. (attribute access)
      - `(str, Enum)` / `(int, IntEnum)` patterns (multi-base)
    """
    enum_names = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in enum_names:
            return True
        if isinstance(base, ast.Attribute) and base.attr in enum_names:
            return True
    return False


def _extract_enum_members(node: ast.ClassDef) -> list[str]:
    """Pull the string values from a Python Enum class body.

    Each member is `NAME = "value"` or `NAME = value`. We prefer the
    string literal value when it exists; otherwise fall back to the
    member name lowercased (matches `auto()`-style declarations).
    """
    members: list[str] = []
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if not isinstance(target, ast.Name):
                continue
            member_name = target.id
            if member_name.startswith("_"):
                continue
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                members.append(stmt.value.value)
            else:
                members.append(member_name.lower())
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            target_name = stmt.target.id
            if target_name.startswith("_"):
                continue
            if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                members.append(stmt.value.value)
            else:
                members.append(target_name.lower())
    # Dedup preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for v in members:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def extract_action_enums(root: Path) -> dict[str, list[str]]:
    """Return `{enum_class_name: [member_value, ...]}` for action-shaped
    Enum classes defined under `root`.

    A class qualifies when:
      - its name matches a known action-enum suffix (`*Action`, `*Tool`,
        `*Intent`, `*Command`, `*Operation`, `*Verb`)
      - AND it inherits from an `Enum` flavor
      - AND it isn't a generic state/status/severity enum (filtered by
        deny-list tokens in the class name)

    Only the first occurrence of each enum name wins (deterministic on
    file walk order). Output is sorted by enum name + member order
    preserved as written.
    """
    out: dict[str, list[str]] = {}
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        tree = parse_python(text)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in out:
                continue
            if not _is_action_enum_name(node.name):
                continue
            if not _is_enum_subclass(node):
                continue
            members = _extract_enum_members(node)
            if members:
                out[node.name] = members
    return dict(sorted(out.items()))


def render_repo_action_policy(
    enums: dict[str, list[str]],
    repo_name: str,
) -> str | None:
    """Render a `tool_use.<repo_name>.v1.yaml` policy seeded with the
    enum values. Returns None when there's nothing to render.

    The generated policy:
      - declares `allowed_actions: [...]` with the union of all detected
        enum members
      - emits a `deny if payload['action'] not in allowed_actions` rule
      - emits a `review if action in <high-blast subset>` rule for
        members whose name shouts mass / deploy / escalate (heuristic)
    """
    if not enums:
        return None

    all_values: list[str] = []
    for members in enums.values():
        for m in members:
            if m not in all_values:
                all_values.append(m)

    high_blast = [
        v for v in all_values
        if any(tok in v.lower() for tok in (
            "mass_", "delete_", "deploy_", "escalate_", "drop_",
            "approve_", "publish_", "send_all", "broadcast",
        ))
    ]

    import json
    allowed_yaml = json.dumps(sorted(all_values), ensure_ascii=False)
    review_yaml = json.dumps(sorted(high_blast), ensure_ascii=False) if high_blast else "[]"

    enum_list = ", ".join(sorted(enums))

    lines = [
        f"name: tool_use.{repo_name}",
        "version: 1",
        "description: >",
        f"  Repo-specific action allowlist generated from the {enum_list} enum(s).",
        "  The agent can only invoke actions that exist in the repo's source-of-truth",
        "  enum — anything else is denied. High-blast actions (mass_*, delete_*,",
        "  deploy_*, escalate_*) go to review by default; trim the review list to",
        "  match your team's tolerance.",
        f"allowed_actions: {allowed_yaml}",
        f"review_actions: {review_yaml}",
        "rules:",
        "  - id: action-allowlist",
        "    when: \"payload.get('action') not in allowed_actions\"",
        "    action: deny",
        "    reason: action-not-in-repo-enum",
        "    explanation: >",
        f"      The action isn't a member of any of the repo's action enums",
        f"      ({enum_list}). Either add it to the enum (intentional new",
        "      capability — review the code path first) or fix the caller.",
        "  - id: high-blast-action-review",
        "    when: \"payload.get('action') in review_actions\"",
        "    action: review",
        "    reason: high-blast-action-needs-human",
        "    explanation: >",
        "      Mass / delete / deploy / escalate actions are gated by review",
        "      so a prompt injection can't fire one without a human signoff.",
        "      Customize `review_actions` to match your team's risk tolerance.",
        "",
    ]
    return "\n".join(lines)
