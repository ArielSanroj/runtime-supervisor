from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import policy as policy_engine
from . import risk as risk_engine
from .policy import Policy, PolicyHit


@dataclass(frozen=True)
class Decision:
    decision: str  # allow|deny|review
    reasons: list[str]
    hits: list[PolicyHit]
    risk_score: int
    risk_breakdown: list[dict[str, Any]]
    policy_version: str


def decide(policy: Policy, payload: dict[str, Any]) -> Decision:
    hits = policy_engine.evaluate(policy, payload)
    deny_hits = [h for h in hits if h.action == "deny"]
    review_hits = [h for h in hits if h.action == "review"]

    if deny_hits:
        return Decision(
            decision="deny",
            reasons=[h.reason for h in deny_hits],
            hits=hits,
            risk_score=0,
            risk_breakdown=[],
            policy_version=policy.version_tag,
        )

    total, breakdown = risk_engine.score(payload)

    if review_hits or risk_engine.needs_review(total):
        reasons = [h.reason for h in review_hits] or [f"risk-score-{total}"]
        return Decision(
            decision="review",
            reasons=reasons,
            hits=hits,
            risk_score=total,
            risk_breakdown=breakdown,
            policy_version=policy.version_tag,
        )

    return Decision(
        decision="allow",
        reasons=["passes-policy-and-risk"],
        hits=hits,
        risk_score=total,
        risk_breakdown=breakdown,
        policy_version=policy.version_tag,
    )
