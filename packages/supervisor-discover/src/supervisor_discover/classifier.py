"""Promote findings to definitive action_types when the suggestion is strong.

This keeps the classifier in one place — when the supervisor's
`registry.py` grows a new action_type, we add a rule here and both the
report and the generated stubs pick it up.
"""
from __future__ import annotations

from .findings import Finding

_ACTION_TYPES = {"refund", "payment", "account_change", "data_access", "tool_use", "compliance", "other"}


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
