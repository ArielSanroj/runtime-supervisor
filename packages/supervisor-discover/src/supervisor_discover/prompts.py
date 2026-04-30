"""LLM-ready prompts that apply the @supervised wrap from a finding.

A finding tells the user *what to do* (the `Fix:` line) and *why* (the
`Problem:` line). This module produces the *how*: a copy-paste prompt the
user pastes into Cursor / Claude Code / Codex so the agent edits the file
end-to-end without manual translation.

Prompt shape — kept stable so users can write tooling around it:

    GOAL: <one sentence, action-oriented>
    CONTEXT: <one or two sentences from rationale>
    TARGET:
      - File: <path>
      - Line: <n>
      - Snippet: `<code>`
    CHANGE:
      <free-text instruction>
      ```<lang>
      <pattern from templates.py>
      ```
    CONSTRAINTS:
      - Behavior identical when SUPERVISOR_ENFORCEMENT_MODE=shadow.
      - …
    Confirm with a unified diff of just `<file>`.

Why a prompt and not a patch? Real call-sites have call-shape variation
(positional vs kwargs, async vs sync, named return value, surrounding
try/except) that a one-shot regex can't get right. A prompt with the
exact target plus a minimal pattern lets the user's LLM produce a
faithful diff without us shipping a code-modifier.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from .findings import Finding

Lang = Literal["py", "ts"]

_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
_PY_EXTS = {".py", ".pyi"}


def _detect_language(file: str) -> Lang:
    suffix = Path(file).suffix.lower()
    if suffix in _TS_EXTS:
        return "ts"
    if suffix in _PY_EXTS:
        return "py"
    return "py"  # default — most stubs ship Python first


# Per-(language, action_type) minimal example. Kept short on purpose: the
# prompt's job is to *direct* the user's LLM, not to be a full how-to. A
# 6-line skeleton converges faster than a 40-line annotated example.
_PY_PATTERNS: dict[str, str] = {
    "payment": (
        "from supervisor_guards import supervised\n\n"
        "@supervised('payment', payload=lambda **kw: {\n"
        "    'amount': kw.get('amount'),\n"
        "    'currency': kw.get('currency'),\n"
        "    'customer_id': kw.get('customer') or kw.get('customer_id'),\n"
        "})\n"
        "def charge(**kwargs):\n"
        "    return stripe.Charge.create(**kwargs)"
    ),
    "tool_use": (
        "from supervisor_guards import supervised\n\n"
        "@supervised('tool_use', payload=lambda **kw: {\n"
        "    'tool': '<tool-name>',  # required by tool_use.base.v1\n"
        "    # add the fields your policy's `when:` expressions reference\n"
        "})\n"
        "def call_tool(**kwargs):\n"
        "    return original_call(**kwargs)"
    ),
    "data_access": (
        "from supervisor_guards import supervised\n\n"
        "@supervised('data_access', payload=lambda **kw: {\n"
        "    'table': '<table-name>',\n"
        "    'verb': '<insert|update|delete|select>',\n"
        "    'where': kw.get('where'),\n"
        "})\n"
        "def run_query(**kwargs):\n"
        "    return db.execute(**kwargs)"
    ),
}

_TS_PATTERNS: dict[str, str] = {
    "payment": (
        "import { supervised } from '@runtime-supervisor/guards';\n\n"
        "const guardedCharge = supervised('payment', {\n"
        "  payloadFrom: (args) => ({\n"
        "    amount: args.amount,\n"
        "    currency: args.currency,\n"
        "    customer_id: args.customer ?? args.customer_id,\n"
        "  }),\n"
        "})(async (args) => stripe.charges.create(args));"
    ),
    "tool_use": (
        "import { supervised } from '@runtime-supervisor/guards';\n\n"
        "const guardedCall = supervised('tool_use', {\n"
        "  payloadFrom: (args) => ({\n"
        "    tool: '<tool-name>',  // required by tool_use.base.v1\n"
        "    // add fields the policy's `when:` references\n"
        "  }),\n"
        "})(async (args) => originalCall(args));"
    ),
    "data_access": (
        "import { supervised } from '@runtime-supervisor/guards';\n\n"
        "const guardedQuery = supervised('data_access', {\n"
        "  payloadFrom: (args) => ({\n"
        "    table: '<table-name>',\n"
        "    verb: '<insert|update|delete|select>',\n"
        "    where: args.where,\n"
        "  }),\n"
        "})(async (args) => db.execute(args));"
    ),
}


def _pattern(language: Lang, action_type: str) -> str:
    table = _PY_PATTERNS if language == "py" else _TS_PATTERNS
    return table.get(action_type, table["tool_use"])


def _payload_hint(action_type: str) -> str:
    """One-line nudge about *which* fields the supervisor will see —
    keeps the prompt anchored to the policy schema without bloating it."""
    return {
        "payment":     "amount / currency / customer_id (cap + velocity policy)",
        "tool_use":    "tool name + the args the policy's `when:` expression references",
        "data_access": "table / verb / where-clause (row-cap + audit policy)",
        "account_change": "user_id / field / new_value",
        "compliance":  "subject / scope / reason",
    }.get(action_type, "the args your policy's `when:` expression references")


def _short_path(file: str) -> str:
    """Drop the absolute prefix so the prompt stays portable across
    workspaces — Cursor / Claude Code resolve relative paths fine."""
    parts = Path(file).parts
    # Try to take the path from the first segment that looks repo-rooted
    for marker in ("src", "app", "apps", "packages", "services", "supabase", "lib"):
        if marker in parts:
            i = parts.index(marker)
            return "/".join(parts[i:])
    # Fallback — last 3 components
    return "/".join(parts[-3:]) if len(parts) >= 3 else file


def prompt_for(finding: Finding, language: Lang | None = None) -> str:
    """Generate a copy-paste LLM prompt that applies the @supervised wrap
    described by the finding's `suggested_action_type`.

    The prompt always includes file:line so the user's LLM doesn't have
    to grep for the call. Behavior is shadow-only by default — never
    block on the first PR.
    """
    lang = language or _detect_language(finding.file)
    file = _short_path(finding.file)
    snippet = (finding.snippet or "").replace("\n", " ").strip()
    if len(snippet) > 120:
        snippet = snippet[:117] + "…"
    action = finding.suggested_action_type or "tool_use"
    pattern = _pattern(lang, action)
    fence = "ts" if lang == "ts" else "python"
    rationale = (finding.rationale or "").strip()

    return (
        f"GOAL: wrap the call at `{file}:{finding.line}` with the runtime "
        f"supervisor so every invocation is policy-checked before it fires. "
        f"Stay in shadow mode by default — this PR must NOT block traffic.\n"
        f"\n"
        f"CONTEXT:\n"
        f"{rationale}\n"
        f"\n"
        f"TARGET:\n"
        f"  - File: {file}\n"
        f"  - Line: {finding.line}\n"
        f"  - Snippet: `{snippet}`\n"
        f"\n"
        f"CHANGE:\n"
        f"Apply the `@supervised('{action}')` pattern around the call. "
        f"Pass {_payload_hint(action)} so per-{action} policies can run.\n"
        f"\n"
        f"```{fence}\n"
        f"{pattern}\n"
        f"```\n"
        f"\n"
        f"CONSTRAINTS:\n"
        f"  - Behavior must be identical when `SUPERVISOR_ENFORCEMENT_MODE=shadow` (the default).\n"
        f"  - Read `SUPERVISOR_BASE_URL`, `SUPERVISOR_APP_ID`, `SUPERVISOR_SECRET` from env.\n"
        f"  - Don't change unrelated code; show me a unified diff of just `{file}`.\n"
        f"  - If the import is already present, don't re-add it.\n"
        f"\n"
        f"Confirm with the diff."
    )


def prompt_for_group(
    findings: list[Finding],
    *,
    label: str,
    action_type: str | None = None,
) -> str:
    """Group prompt for a PriorityItem that bundles N call-sites.

    The user pastes one prompt and the LLM runs the same wrap across the
    listed targets. We don't pick a single language — let the LLM detect
    per-file. We list up to 12 targets explicitly; beyond that, the user's
    agent should grep for `findings.json` to enumerate.
    """
    if not findings:
        return ""

    primary = findings[0]
    action = action_type or primary.suggested_action_type or "tool_use"
    py_pattern = _pattern("py", action)
    ts_pattern = _pattern("ts", action)
    rationale = (primary.rationale or "").strip()

    target_lines = []
    for f in findings[:12]:
        target_lines.append(f"  - {_short_path(f.file)}:{f.line}")
    if len(findings) > 12:
        target_lines.append(f"  - …and {len(findings) - 12} more (see `runtime-supervisor/findings.json`)")

    return (
        f"GOAL: {label.lower()} — wrap each listed call-site with `@supervised('{action}')` "
        f"so the runtime supervisor gates every invocation. Stay in shadow mode by default; "
        f"this PR must NOT block traffic.\n"
        f"\n"
        f"CONTEXT:\n"
        f"{rationale}\n"
        f"\n"
        f"TARGETS:\n"
        + "\n".join(target_lines) + "\n"
        f"\n"
        f"CHANGE — pick the language each file already uses:\n"
        f"\n"
        f"Python pattern:\n"
        f"```python\n{py_pattern}\n```\n"
        f"\n"
        f"TypeScript pattern:\n"
        f"```ts\n{ts_pattern}\n```\n"
        f"\n"
        f"CONSTRAINTS:\n"
        f"  - Behavior must be identical when `SUPERVISOR_ENFORCEMENT_MODE=shadow` (the default).\n"
        f"  - Read `SUPERVISOR_BASE_URL`, `SUPERVISOR_APP_ID`, `SUPERVISOR_SECRET` from env.\n"
        f"  - Pass the supervisor `{_payload_hint(action)}` in the payload.\n"
        f"  - Touch only the files listed in TARGETS. Don't refactor unrelated code.\n"
        f"  - If the import is already present in a file, don't re-add it.\n"
        f"\n"
        f"Confirm with one unified diff per file."
    )
