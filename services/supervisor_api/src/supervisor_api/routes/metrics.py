"""Aggregated metrics for the ops dashboard.

Pure counts over the existing tables — cheap queries, no instrumentation.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Action, ActionExecution, Decision, Integration, ReviewItem, ThreatAssessmentRow

router = APIRouter(prefix="/v1", tags=["metrics"])

Window = Literal["24h", "7d", "30d"]

_WINDOW_DELTAS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def _since(window: str) -> datetime:
    delta = _WINDOW_DELTAS.get(window, _WINDOW_DELTAS["24h"])
    return datetime.now(UTC) - delta


@router.get("/metrics/summary")
def metrics_summary(
    window: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    since = _since(window)

    # Total actions in the window — tenant-scoped.
    actions_total = db.execute(
        select(func.count())
        .select_from(Action)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
    ).scalar_one()

    # Decision breakdown (joined via Action so window + tenant inherit).
    decision_rows = db.execute(
        select(Decision.decision, func.count())
        .join(Action, Action.id == Decision.action_id)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .group_by(Decision.decision)
    ).all()
    decisions = {"allow": 0, "deny": 0, "review": 0}
    for d, n in decision_rows:
        decisions[d] = n

    # Threats by level
    threat_rows = db.execute(
        select(ThreatAssessmentRow.level, func.count())
        .where(ThreatAssessmentRow.created_at >= since)
        .where(ThreatAssessmentRow.tenant_id == tenant_id)
        .group_by(ThreatAssessmentRow.level)
    ).all()
    threats = {"critical": 0, "warn": 0, "info": 0}
    for lvl, n in threat_rows:
        threats[lvl] = n
    threats_total = sum(threats.values())

    # Threats by detector (top 5)
    detector_rows = db.execute(
        select(ThreatAssessmentRow.detector_id, func.count())
        .where(ThreatAssessmentRow.created_at >= since)
        .where(ThreatAssessmentRow.tenant_id == tenant_id)
        .group_by(ThreatAssessmentRow.detector_id)
        .order_by(func.count().desc())
        .limit(5)
    ).all()
    top_detectors = [{"detector_id": d, "count": n} for d, n in detector_rows]

    # Reviews by status (open pending doesn't care about window — always current)
    review_status_rows = db.execute(
        select(ReviewItem.status, func.count())
        .where(ReviewItem.tenant_id == tenant_id)
        .group_by(ReviewItem.status)
    ).all()
    reviews = {"pending": 0, "approved": 0, "rejected": 0}
    for s, n in review_status_rows:
        reviews[s] = n

    oldest_pending = db.execute(
        select(func.min(ReviewItem.created_at))
        .where(ReviewItem.status == "pending")
        .where(ReviewItem.tenant_id == tenant_id)
    ).scalar_one()
    oldest_age_minutes = None
    if oldest_pending is not None:
        # normalize tz
        if oldest_pending.tzinfo is None:
            oldest_pending = oldest_pending.replace(tzinfo=UTC)
        oldest_age_minutes = max(0, int((datetime.now(UTC) - oldest_pending).total_seconds() // 60))

    # Executions in the window
    exec_rows = db.execute(
        select(ActionExecution.state, func.count())
        .where(ActionExecution.queued_at >= since)
        .where(ActionExecution.tenant_id == tenant_id)
        .group_by(ActionExecution.state)
    ).all()
    executions = {"success": 0, "failed": 0, "pending": 0}
    for s, n in exec_rows:
        executions[s] = n
    exec_total = sum(executions.values())
    exec_success_rate = (executions["success"] / exec_total) if exec_total else None

    # Active integrations count (this tenant only).
    active_integrations = db.execute(
        select(func.count())
        .select_from(Integration)
        .where(Integration.active.is_(True))
        .where(Integration.tenant_id == tenant_id)
    ).scalar_one()

    # Policy active count by action_type. Policies remain global-admin-owned
    # today (Phase 3 will add tenant-scoped overrides); count all actives so
    # the dashboard reflects what the supervisor actually evaluates against.
    from ..models import PolicyRecord

    active_policies = db.execute(
        select(PolicyRecord.action_type, func.count())
        .where(PolicyRecord.is_active.is_(True))
        .group_by(PolicyRecord.action_type)
    ).all()
    active_policies_by_type = {at: n for at, n in active_policies}

    # Volume by action_type in window
    volume_by_type_rows = db.execute(
        select(Action.action_type, func.count())
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .group_by(Action.action_type)
    ).all()
    volume_by_type = {at: n for at, n in volume_by_type_rows}

    return {
        "window": window,
        "since": since.isoformat(),
        "actions_total": actions_total,
        "decisions": decisions,
        "threats": {"total": threats_total, **threats, "top_detectors": top_detectors},
        "reviews": {**reviews, "oldest_pending_age_minutes": oldest_age_minutes},
        "executions": {**executions, "success_rate": exec_success_rate, "total": exec_total},
        "active_integrations": active_integrations,
        "active_policies_by_type": active_policies_by_type,
        "volume_by_action_type": volume_by_type,
    }


def _percentile(values: list[int], p: float) -> int | None:
    """Nearest-rank percentile on a pre-sorted list; None when empty."""
    if not values:
        return None
    values_sorted = sorted(values)
    k = max(0, min(len(values_sorted) - 1, int(round((p / 100.0) * (len(values_sorted) - 1)))))
    return values_sorted[k]


@router.get("/metrics/enforcement")
def metrics_enforcement(
    window: str = Query(default="7d", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """Shadow-vs-enforce diff for the rollout playbook.

    Numbers an operator needs to decide when to flip `enforcement_mode` from
    shadow to enforce:

    - `would_block_in_shadow`: deny/review decisions that shadow calls made
      but were NOT surfaced to the caller. Non-zero here means enforce mode
      would start blocking that many calls.
    - `actually_blocked`: deny decisions on enforced calls.
    - `blocks_later_approved_by_reviewer`: of the enforced review cases,
      how many a human later approved. Proxy for false-positive rate on
      escalations.
    - `latency_ms`: p50/p95/p99 of the evaluate call itself. Upper bound on
      friction added per guarded call (real overhead includes network RTT
      to the supervisor, not just server time).
    """
    since = _since(window)

    totals = db.execute(
        select(Action.shadow, func.count())
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .group_by(Action.shadow)
    ).all()
    shadow_evaluations = 0
    enforced_evaluations = 0
    for is_shadow, n in totals:
        if is_shadow:
            shadow_evaluations = n
        else:
            enforced_evaluations = n

    # Shadow decisions that would have blocked (deny or review).
    would_block_in_shadow = db.execute(
        select(func.count())
        .select_from(Decision)
        .join(Action, Action.id == Decision.action_id)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .where(Action.shadow.is_(True))
        .where(Decision.decision.in_(("deny", "review")))
    ).scalar_one()

    actually_blocked = db.execute(
        select(func.count())
        .select_from(Decision)
        .join(Action, Action.id == Decision.action_id)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .where(Action.shadow.is_(False))
        .where(Decision.decision == "deny")
    ).scalar_one()

    # Review outcomes only exist on enforced calls (shadow never creates a
    # ReviewItem). Approvals of escalated calls are the closest proxy for
    # "we escalated, but turns out it was fine" — i.e. false positive.
    review_outcomes = db.execute(
        select(ReviewItem.status, func.count())
        .join(Action, Action.id == ReviewItem.action_id)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .group_by(ReviewItem.status)
    ).all()
    review_counts = {"pending": 0, "approved": 0, "rejected": 0}
    for s, n in review_outcomes:
        review_counts[s] = n
    resolved = review_counts["approved"] + review_counts["rejected"]
    estimated_fp_rate = (review_counts["approved"] / resolved) if resolved else None

    # Latency — pull the last N rows' latency_ms column, compute percentiles.
    # O(N) is fine for N=10k; promote to a histogram when we outgrow this.
    latencies = db.execute(
        select(Decision.latency_ms)
        .join(Action, Action.id == Decision.action_id)
        .where(Action.created_at >= since)
        .where(Action.tenant_id == tenant_id)
        .where(Decision.latency_ms.is_not(None))
        .order_by(Decision.created_at.desc())
        .limit(10000)
    ).scalars().all()
    latencies_list = [int(x) for x in latencies if x is not None]

    total_evaluations = shadow_evaluations + enforced_evaluations
    return {
        "window": window,
        "since": since.isoformat(),
        "total_evaluations": total_evaluations,
        "shadow_evaluations": shadow_evaluations,
        "enforced_evaluations": enforced_evaluations,
        "would_block_in_shadow": would_block_in_shadow,
        "actually_blocked": actually_blocked,
        "reviews": review_counts,
        "blocks_later_approved_by_reviewer": review_counts["approved"],
        "estimated_false_positive_rate": estimated_fp_rate,
        "latency_ms": {
            "p50": _percentile(latencies_list, 50),
            "p95": _percentile(latencies_list, 95),
            "p99": _percentile(latencies_list, 99),
            "samples": len(latencies_list),
        },
    }
