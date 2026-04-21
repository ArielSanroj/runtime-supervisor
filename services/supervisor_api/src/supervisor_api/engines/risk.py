"""Risk scoring — dispatches to per-action-type rule sets.

Each supervisor has its own risk signature; refund cares about customer age
and refund velocity, payment cares about vendor tenure and approval chain,
etc. Adding a new action_type = add a new `_score_<type>` function and wire
it into `_SCORERS`.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

REVIEW_THRESHOLD = 50

ScoreResult = tuple[int, list[dict[str, Any]]]


def _amount(payload: dict[str, Any]) -> float:
    v = payload.get("amount", 0)
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _score_refund(payload: dict[str, Any]) -> ScoreResult:
    breakdown: list[dict[str, Any]] = []
    total = 0

    if _amount(payload) > 1000:
        breakdown.append({"rule": "amount-over-1000", "points": 30})
        total += 30

    age = payload.get("customer_age_days")
    if isinstance(age, int) and age < 30:
        breakdown.append({"rule": "new-customer-lt-30d", "points": 20})
        total += 20

    velocity = payload.get("refund_velocity_24h", 0)
    if isinstance(velocity, int) and velocity > 3:
        breakdown.append({"rule": "refund-velocity-over-3", "points": 40})
        total += 40

    reason = payload.get("reason")
    if reason in (None, "other", "no_reason"):
        breakdown.append({"rule": "vague-reason", "points": 20})
        total += 20

    return total, breakdown


def _score_payment(payload: dict[str, Any]) -> ScoreResult:
    breakdown: list[dict[str, Any]] = []
    total = 0

    amount = _amount(payload)
    if amount > 10000:
        breakdown.append({"rule": "amount-over-10k", "points": 30})
        total += 30

    vendor_tenure = payload.get("vendor_first_seen_days")
    if isinstance(vendor_tenure, int) and vendor_tenure < 30:
        breakdown.append({"rule": "new-vendor-lt-30d", "points": 30})
        total += 30

    if bool(payload.get("bank_account_changed")):
        breakdown.append({"rule": "bank-account-changed", "points": 40})
        total += 40

    chain = payload.get("approval_chain") or []
    if amount > 5000 and (not isinstance(chain, list) or len(chain) == 0):
        breakdown.append({"rule": "approval-chain-missing-on-mid-amount", "points": 40})
        total += 40

    return total, breakdown


def _score_tool_use(payload: dict[str, Any]) -> ScoreResult:
    """LLM tool-call risk: size, tool privileges, prompt length."""
    breakdown: list[dict[str, Any]] = []
    total = 0

    prompt = payload.get("prompt") or payload.get("messages") or ""
    prompt_len = len(str(prompt))
    if prompt_len > 50_000:
        breakdown.append({"rule": "prompt-over-50k", "points": 30})
        total += 30
    elif prompt_len > 20_000:
        breakdown.append({"rule": "prompt-over-20k", "points": 15})
        total += 15

    max_tokens = payload.get("max_tokens")
    if isinstance(max_tokens, int) and max_tokens > 4000:
        breakdown.append({"rule": "max-tokens-over-4k", "points": 15})
        total += 15

    tool = str(payload.get("tool") or "")
    privileged_prefixes = ("system.", "fs.", "network.", "exec.", "shell.")
    if any(tool.startswith(p) for p in privileged_prefixes):
        breakdown.append({"rule": "privileged-tool-namespace", "points": 40})
        total += 40

    if not tool:
        breakdown.append({"rule": "missing-tool-name", "points": 20})
        total += 20

    return total, breakdown


def _score_account_change(payload: dict[str, Any]) -> ScoreResult:
    """Account-change risk: privilege changes, fresh accounts, multi-field edits."""
    breakdown: list[dict[str, Any]] = []
    total = 0

    # Multi-field identity changes look like takeover even if individually OK
    sensitive = sum(1 for k in ("new_email", "new_phone", "new_password") if k in payload)
    if sensitive >= 2:
        breakdown.append({"rule": "multi-identity-change", "points": 40})
        total += 40
    elif sensitive == 1:
        breakdown.append({"rule": "single-identity-change", "points": 15})
        total += 15

    new_role = str(payload.get("new_role") or "").lower()
    if new_role in ("admin", "owner", "superuser", "root"):
        breakdown.append({"rule": "role-to-admin-tier", "points": 40})
        total += 40

    age = payload.get("customer_age_days")
    if isinstance(age, int) and age < 30 and sensitive >= 1:
        breakdown.append({"rule": "change-on-fresh-account", "points": 20})
        total += 20

    return total, breakdown


def _score_data_access(payload: dict[str, Any]) -> ScoreResult:
    """Data-access risk: scope, sensitive columns, missing tenant."""
    breakdown: list[dict[str, Any]] = []
    total = 0

    row_limit = payload.get("row_limit", 0)
    if isinstance(row_limit, int):
        if row_limit == 0 or row_limit > 10_000:
            breakdown.append({"rule": "unbounded-scope", "points": 30})
            total += 30
        elif row_limit > 1000:
            breakdown.append({"rule": "wide-scope-gt-1000", "points": 15})
            total += 15

    proj = str(payload.get("projection") or "").lower()
    for pii in ("credit_card", "card_number", "ssn", "social_security", "cvv", "pin_code", "passport"):
        if pii in proj:
            breakdown.append({"rule": f"pii-column-{pii}", "points": 40})
            total += 40
            break

    if payload.get("operation") in ("read", "update", "delete") and not payload.get("tenant_id"):
        breakdown.append({"rule": "missing-tenant-scope", "points": 30})
        total += 30

    return total, breakdown


def _score_compliance(payload: dict[str, Any]) -> ScoreResult:
    """Compliance actions default to review — err on the side of humans."""
    breakdown: list[dict[str, Any]] = []
    # High baseline: compliance flows always start near the review threshold.
    # Specific rules in compliance.base.v1.yaml can still allow/deny explicitly.
    breakdown.append({"rule": "compliance-baseline", "points": 30})
    total = 30

    kind = str(payload.get("kind") or payload.get("alert_type") or "").lower()
    if kind in ("aml_close", "kyc_override", "gdpr_delete", "sanctions_review"):
        breakdown.append({"rule": f"regulated-flow-{kind}", "points": 30})
        total += 30

    if payload.get("reviewer_confidence") and float(payload["reviewer_confidence"]) < 0.6:
        breakdown.append({"rule": "low-reviewer-confidence", "points": 20})
        total += 20

    return total, breakdown


_SCORERS: dict[str, Callable[[dict[str, Any]], ScoreResult]] = {
    "refund": _score_refund,
    "payment": _score_payment,
    "tool_use": _score_tool_use,
    "account_change": _score_account_change,
    "data_access": _score_data_access,
    "compliance": _score_compliance,
}


def _score_default(payload: dict[str, Any]) -> ScoreResult:
    """Unknown action_type — no signals, zero score. The policy engine still
    runs; if no policy matches, the action is allowed by default. Explicit
    zero is safer than falling through to a domain-specific scorer (refund)
    that would report false positives on tool_use / data_access / etc."""
    return 0, []


def score(payload: dict[str, Any], action_type: str = "refund") -> ScoreResult:
    scorer = _SCORERS.get(action_type, _score_default)
    return scorer(payload)


def needs_review(total: int) -> bool:
    return total >= REVIEW_THRESHOLD
