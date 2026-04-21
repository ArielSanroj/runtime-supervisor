"""Optional --refine pass: enrich per-finding narratives with Claude.

Every other module in this package is deterministic (no LLM, no network).
This one is the escape hatch — when the operator wants a report that reads
like a security reviewer wrote it, they pass `--refine` and Claude rewrites
the narratives using the repo's specific context (filenames, surrounding
code, combo context).

Usage:
    supervisor-discover scan --refine

Requires `ANTHROPIC_API_KEY` in the environment. No key → prints a warning
and falls back to deterministic narratives. Never blocks the scan.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import replace
from typing import Any

from .combos import Combo
from .findings import Finding
from .summary import RepoSummary

log = logging.getLogger(__name__)

# How many findings to send in one Claude call. Claude handles way more than
# this, but we cap for cost/latency — top high-confidence findings first.
_MAX_FINDINGS_PER_CALL = 20

_SYSTEM_PROMPT = """You are a security engineer reviewing an AI agent's codebase.
You'll receive:
  (a) a `repo_summary` describing the stack, integrations, and detected real-world actions,
  (b) a list of `findings` (call-sites detected by static scanners),
  (c) optional `combos` (dangerous pairs of capabilities found in this repo).

Your job: rewrite each finding's `rationale` so it reads like a short security
review note specific to THIS repo. Be concrete about what goes wrong if a prompt
injection succeeds at that call-site. Two sentences max per finding. No bullet
points, no markdown. Plain prose.

Constraints:
- Stay concrete to the repo — reference file names when helpful.
- Never invent facts not present in the input.
- Language: Spanish neutral (matches the rest of the report).
- Output JSON exactly matching the schema below.

Schema (return exactly this shape):
{
  "refined": [
    {"index": <int>, "rationale": "<1-2 sentences in Spanish>"}
  ]
}
"""


def _safe_import_anthropic():
    """Return (anthropic_module, api_key) or (None, None) if unavailable."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None, None
    try:
        import anthropic
        return anthropic, api_key
    except ImportError:
        return None, None


def _findings_payload(findings: list[Finding], limit: int) -> tuple[list[dict[str, Any]], list[int]]:
    """Pick up to `limit` findings worth refining (high first, then medium).
    Returns (payload_list, original_indices)."""
    ranked = sorted(
        enumerate(findings),
        key=lambda p: (0 if p[1].confidence == "high" else 1, p[0]),
    )
    picked = ranked[:limit]
    payload = [
        {
            "index": orig_idx,
            "scanner": f.scanner,
            "file": f.file.split("/")[-1],
            "line": f.line,
            "snippet": f.snippet,
            "provider": f.extra.get("provider") or f.extra.get("family") or "",
            "current_rationale": f.rationale[:400],
        }
        for orig_idx, f in picked
    ]
    return payload, [orig_idx for orig_idx, _ in picked]


def refine_findings(
    findings: list[Finding],
    summary: RepoSummary,
    combos: list[Combo],
    model: str = "claude-sonnet-4-6",
) -> list[Finding]:
    """Call Claude once; replace the top-N findings' rationales with repo-specific
    narratives. Returns a new list (input is not mutated). If Claude is
    unavailable or errors out, returns the input unchanged with a warning."""
    anthropic_mod, api_key = _safe_import_anthropic()
    if not anthropic_mod:
        log.warning(
            "--refine requested but anthropic SDK or ANTHROPIC_API_KEY not available; "
            "falling back to deterministic narratives. "
            "Install: pip install anthropic + export ANTHROPIC_API_KEY=..."
        )
        return findings

    if not findings:
        return findings

    payload, indices = _findings_payload(findings, _MAX_FINDINGS_PER_CALL)
    user_message = json.dumps(
        {
            "repo_summary": {
                "frameworks": summary.frameworks,
                "payment_integrations": summary.payment_integrations,
                "llm_providers": summary.llm_providers,
                "real_world_actions": summary.real_world_actions,
                "sensitive_tables": summary.sensitive_tables,
                "http_routes": summary.http_routes,
            },
            "combos": [
                {"title": c.title, "severity": c.severity, "narrative": c.narrative[:200]}
                for c in combos
            ],
            "findings": payload,
        },
        ensure_ascii=False,
    )

    try:
        client = anthropic_mod.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=4000,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        text = "".join(
            block.text for block in response.content if hasattr(block, "text")
        ).strip()
    except Exception as exc:  # noqa: BLE001
        log.warning("refine pass failed (%s); using deterministic narratives", exc)
        return findings

    # Parse Claude's JSON. Be defensive — fenced markdown, extra prose, etc.
    try:
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        parsed = json.loads(text.strip())
        refined = parsed.get("refined", [])
    except (json.JSONDecodeError, KeyError) as exc:
        log.warning("could not parse refine response (%s); keeping original", exc)
        return findings

    # Build a map of original_index → new rationale
    index_to_rationale: dict[int, str] = {}
    for item in refined:
        if not isinstance(item, dict):
            continue
        idx = item.get("index")
        rationale = item.get("rationale")
        if isinstance(idx, int) and isinstance(rationale, str) and rationale.strip():
            index_to_rationale[idx] = rationale.strip()

    # Return new list with refined rationales substituted in
    return [
        replace(f, rationale=index_to_rationale[i]) if i in index_to_rationale else f
        for i, f in enumerate(findings)
    ]
