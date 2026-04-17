from __future__ import annotations

from dataclasses import dataclass
from typing import Any

REVIEW_THRESHOLD = 50


@dataclass(frozen=True)
class RiskRule:
    name: str
    points: int


def _amount(payload: dict[str, Any]) -> float:
    v = payload.get("amount", 0)
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def score(payload: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
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


def needs_review(total: int) -> bool:
    return total >= REVIEW_THRESHOLD
