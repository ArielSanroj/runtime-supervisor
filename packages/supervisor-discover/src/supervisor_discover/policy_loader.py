"""Load tunable scan-output knobs from packages/policies/scan_output.base.v1.yaml.

The YAML is the single source of truth for: max wrap targets, label_map (internal
action_type → human label), forbidden_words (banned in headlines), capability
phrases (scanner family → "send emails" etc.), default-hidden dirs, and the
priority confidence gate. Anything user-facing should read from here so behavior
is tunable without touching code.

Module-level cache: the YAML is read once on first call and reused. Tests that
need a different policy can call `load_scan_output_policy.cache_clear()`.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# Resolve packages/policies/ relative to this file (.../supervisor_discover/policy_loader.py)
# → parents[4] is the monorepo root.
_POLICY_DIR = Path(__file__).resolve().parents[4] / "packages" / "policies"
_SCAN_OUTPUT_POLICY = _POLICY_DIR / "scan_output.base.v1.yaml"


# Fallback used when the YAML is missing or malformed — keeps the scanner usable
# in edge environments (e.g. when installed as a wheel without packages/policies/).
_FALLBACK: dict[str, Any] = {
    "max_wrap_targets": 3,
    "max_top_risks": 3,
    "forbidden_words": [
        "OWASP", "CVSS", "compliance", "RCE-equivalent",
        "exfiltration", "account takeover",
    ],
    "label_map": {
        "payment": "money movement",
        "refund": "refunds",
        "tool_use": "tool or LLM execution",
        "account_change": "user/account state changes",
        "data_access": "customer/business data access",
        "general": "inventory",
    },
    "capability_phrases": {
        "payment-calls": "move money",
        "email-sends": "send emails",
        "messaging": "call messaging tools",
        "voice-actions": "place phone or voice calls",
        "calendar-actions": "create calendar events",
        "fs-shell-shell-exec": "run shell commands",
        "fs-shell-fs-delete": "delete files",
        "fs-shell-fs-write": "write files",
        "llm-calls": "call LLMs",
        "db-mutations-write": "write to the database",
        "db-mutations-delete": "delete database rows",
        "media-gen": "generate images / audio / video",
        "agent-orchestrators": "run an agent loop",
    },
    "default_hidden_dirs": {
        "tests": ["tests", "test", "__tests__", "spec", "specs"],
        "legacy": ["legacy", "archive", "deprecated", "old"],
        "migrations": ["migrations", "migrate"],
        "generated": ["generated", "gen"],
    },
    "public_output": {
        "show_priority_confidence": ["high"],
        "hide_priority_confidence": ["medium", "low"],
        "general_tier_unfiltered": True,
    },
    "risk_severity": {
        "payment-calls": 100,
        "fs-shell-shell-exec": 90,
        "fs-shell-fs-delete": 80,
        "email-sends": 70,
        "messaging": 60,
        "fs-shell-fs-write": 55,
        "db-mutations-delete": 50,
        "db-mutations-write": 40,
        "llm-calls": 30,
        "agent-orchestrators": 20,
    },
}


@lru_cache(maxsize=1)
def load_scan_output_policy() -> dict[str, Any]:
    """Return the parsed scan-output policy. Falls back to the in-code defaults
    if the YAML can't be read or parsed — never raises during scanner runtime."""
    try:
        text = _SCAN_OUTPUT_POLICY.read_text()
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict):
            return _FALLBACK
        # Shallow-merge with fallback so missing keys don't crash callers.
        merged = {**_FALLBACK, **parsed}
        return merged
    except (OSError, yaml.YAMLError):
        return _FALLBACK


def hidden_dirs_set(policy: dict[str, Any] | None = None) -> set[str]:
    """Flatten default_hidden_dirs into a single set of dir names. Used by
    scanner _walk() to skip-and-count instead of returning the per-category map."""
    p = policy or load_scan_output_policy()
    out: set[str] = set()
    for dirs in (p.get("default_hidden_dirs") or {}).values():
        out.update(dirs)
    return out


def hidden_dirs_by_category(policy: dict[str, Any] | None = None) -> dict[str, set[str]]:
    """Return {category: {dir_name, ...}} so the scanner can attribute each
    skipped path to a counter bucket (tests / legacy / migrations / generated)."""
    p = policy or load_scan_output_policy()
    return {cat: set(dirs) for cat, dirs in (p.get("default_hidden_dirs") or {}).items()}
