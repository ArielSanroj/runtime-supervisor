"""Promote findings to definitive action_types when the suggestion is strong.

This keeps the classifier in one place — when the supervisor's
`registry.py` grows a new action_type, we add a rule here and both the
report and the generated stubs pick it up.
"""
from __future__ import annotations

from typing import Literal

from .findings import Finding

_ACTION_TYPES = {"refund", "payment", "account_change", "data_access", "tool_use", "compliance", "other"}

# Risk tiers — the report orders findings worst-first so readers see the
# highest-impact surfaces before the informational ones.
#
# real_world_actions was added after observing that the 4 original tiers
# (money / customer_data / llm / general) don't cover agents that make phone
# calls, send emails, post to slack, exec shell, write files, or generate
# media. Those are the highest-impact actions for most non-e-commerce agents.
Tier = Literal["money", "real_world_actions", "customer_data", "llm", "general"]

TIER_ORDER: list[Tier] = ["money", "real_world_actions", "customer_data", "llm", "general"]

# Scanner → tier map. Kept separate from `tier_of()` so it can be reused by
# the summary/report rendering without duplicating the switch.
_SCANNER_TO_TIER: dict[str, Tier] = {
    "payment-calls": "money",
    "db-mutations": "customer_data",
    "llm-calls": "llm",
    "voice-actions": "real_world_actions",
    "messaging": "real_world_actions",
    "email-sends": "real_world_actions",
    "calendar-actions": "real_world_actions",
    "fs-shell": "real_world_actions",
    "media-gen": "real_world_actions",
    # http-routes, cron-schedules, anything else → general (fallback below)
}


def validate(findings: list[Finding]) -> list[Finding]:
    """Replace unknown `suggested_action_type` with `other`. Scanners are the
    authority on classification, this just enforces the registry contract."""
    for f in findings:
        if f.suggested_action_type not in _ACTION_TYPES:
            f.suggested_action_type = "other"
    return findings


def group_by_action_type(findings: list[Finding]) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(f.suggested_action_type, []).append(f)
    return buckets


def tier_of(finding: Finding) -> Tier:
    """Map a finding to a risk tier. The tier — not the action_type — drives
    the report's ordering and tone (worst-first in the report)."""
    return _SCANNER_TO_TIER.get(finding.scanner, "general")


def group_by_risk_tier(findings: list[Finding]) -> dict[Tier, list[Finding]]:
    buckets: dict[Tier, list[Finding]] = {t: [] for t in TIER_ORDER}
    for f in findings:
        buckets[tier_of(f)].append(f)
    return buckets
