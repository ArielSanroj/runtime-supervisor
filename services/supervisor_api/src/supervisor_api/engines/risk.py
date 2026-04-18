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


_SCORERS: dict[str, Callable[[dict[str, Any]], ScoreResult]] = {
    "refund": _score_refund,
    "payment": _score_payment,
}


def score(payload: dict[str, Any], action_type: str = "refund") -> ScoreResult:
    scorer = _SCORERS.get(action_type, _score_refund)
    return scorer(payload)


def needs_review(total: int) -> bool:
    return total >= REVIEW_THRESHOLD
