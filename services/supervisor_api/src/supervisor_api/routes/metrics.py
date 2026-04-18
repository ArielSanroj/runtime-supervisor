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
) -> dict[str, Any]:
    since = _since(window)

    # Total actions in the window
    actions_total = db.execute(
        select(func.count()).select_from(Action).where(Action.created_at >= since)
    ).scalar_one()

    # Decision breakdown (joined via Action.created_at so planned/denied before window excluded)
    decision_rows = db.execute(
        select(Decision.decision, func.count())
        .join(Action, Action.id == Decision.action_id)
        .where(Action.created_at >= since)
        .group_by(Decision.decision)
    ).all()
    decisions = {"allow": 0, "deny": 0, "review": 0}
    for d, n in decision_rows:
        decisions[d] = n

    # Threats by level
    threat_rows = db.execute(
        select(ThreatAssessmentRow.level, func.count())
        .where(ThreatAssessmentRow.created_at >= since)
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
        .group_by(ThreatAssessmentRow.detector_id)
        .order_by(func.count().desc())
        .limit(5)
    ).all()
    top_detectors = [{"detector_id": d, "count": n} for d, n in detector_rows]

    # Reviews by status (open pending doesn't care about window — always current)
    review_status_rows = db.execute(
        select(ReviewItem.status, func.count()).group_by(ReviewItem.status)
    ).all()
    reviews = {"pending": 0, "approved": 0, "rejected": 0}
    for s, n in review_status_rows:
        reviews[s] = n

    oldest_pending = db.execute(
        select(func.min(ReviewItem.created_at)).where(ReviewItem.status == "pending")
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
        .group_by(ActionExecution.state)
    ).all()
    executions = {"success": 0, "failed": 0, "pending": 0}
    for s, n in exec_rows:
        executions[s] = n
    exec_total = sum(executions.values())
    exec_success_rate = (executions["success"] / exec_total) if exec_total else None

    # Active integrations count (all-time)
    active_integrations = db.execute(
        select(func.count()).select_from(Integration).where(Integration.active.is_(True))
    ).scalar_one()

    # Policy active count by action_type
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
