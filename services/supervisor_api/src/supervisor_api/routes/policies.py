"""Policy editor endpoints — admin-managed DB store.

The supervisor's evaluator prefers DB-active policies over checked-in YAML.
These endpoints let non-engineers author, test, promote, and deactivate
policies without a code change.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..engines import decision as decision_engine
from ..engines.policy import Policy, compile_policy_yaml
from ..models import Action, Decision, PolicyRecord
from ..schemas import (
    PolicyCreate,
    PolicyOut,
    PolicyReplayResult,
    PolicyTestRequest,
    PolicyTestResult,
    ReplayDivergence,
)

router = APIRouter(prefix="/v1/policies", tags=["policies"], dependencies=[Depends(auth.require_admin)])


def _to_out(p: PolicyRecord) -> PolicyOut:
    return PolicyOut(
        id=p.id, action_type=p.action_type, name=p.name, version=p.version,
        yaml_source=p.yaml_source, is_active=p.is_active,
        created_by=p.created_by, created_at=p.created_at,
        deactivated_at=p.deactivated_at,
    )


@router.post("", response_model=PolicyOut, status_code=201)
def create_policy(body: PolicyCreate, db: Session = Depends(get_db)) -> PolicyOut:
    try:
        parsed: Policy = compile_policy_yaml(body.yaml_source)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"invalid policy: {e}") from e

    # Auto-increment version per action_type
    next_version = (db.execute(
        select(func.coalesce(func.max(PolicyRecord.version), 0))
        .where(PolicyRecord.action_type == body.action_type)
    ).scalar_one() or 0) + 1

    record = PolicyRecord(
        action_type=body.action_type,
        name=parsed.name,
        version=next_version,
        yaml_source=body.yaml_source,
        is_active=False,
    )
    db.add(record)
    db.flush()

    if body.promote:
        _deactivate_others(db, body.action_type, except_id=record.id)
        record.is_active = True

    db.commit()
    db.refresh(record)
    return _to_out(record)


@router.get("", response_model=list[PolicyOut])
def list_policies(
    action_type: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> list[PolicyOut]:
    q = select(PolicyRecord).order_by(PolicyRecord.action_type.asc(), PolicyRecord.version.desc())
    if action_type:
        q = q.where(PolicyRecord.action_type == action_type)
    if active_only:
        q = q.where(PolicyRecord.is_active.is_(True))
    rows = db.execute(q).scalars().all()
    return [_to_out(p) for p in rows]


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(policy_id: str, db: Session = Depends(get_db)) -> PolicyOut:
    p = db.get(PolicyRecord, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    return _to_out(p)


@router.post("/{policy_id}/promote", response_model=PolicyOut)
def promote_policy(policy_id: str, db: Session = Depends(get_db)) -> PolicyOut:
    p = db.get(PolicyRecord, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if p.is_active:
        return _to_out(p)
    _deactivate_others(db, p.action_type, except_id=p.id)
    p.is_active = True
    p.deactivated_at = None
    db.commit()
    db.refresh(p)
    return _to_out(p)


@router.post("/{policy_id}/deactivate", response_model=PolicyOut)
def deactivate_policy(policy_id: str, db: Session = Depends(get_db)) -> PolicyOut:
    p = db.get(PolicyRecord, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    p.is_active = False
    p.deactivated_at = datetime.now(UTC)
    db.commit()
    db.refresh(p)
    return _to_out(p)


@router.post("/{policy_id}/test", response_model=PolicyTestResult)
def test_policy(policy_id: str, body: PolicyTestRequest, db: Session = Depends(get_db)) -> PolicyTestResult:
    p = db.get(PolicyRecord, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    try:
        compiled = compile_policy_yaml(p.yaml_source)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"stored policy no longer compiles: {e}") from e

    dec = decision_engine.decide(compiled, body.payload, action_type=p.action_type)
    return PolicyTestResult(
        decision=dec.decision,  # type: ignore[arg-type]
        hits=[{"rule_id": h.rule_id, "action": h.action, "reason": h.reason} for h in dec.hits],
        reasons=dec.reasons,
    )


_REPLAY_WINDOWS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_TIGHTEN_ORDER = {"allow": 0, "review": 1, "deny": 2}


@router.post("/{policy_id}/replay", response_model=PolicyReplayResult)
def replay_policy(
    policy_id: str,
    window: str = Query(default="7d", pattern="^(24h|7d|30d)$"),
    limit: int = Query(default=200, ge=1, le=2000),
    db: Session = Depends(get_db),
) -> PolicyReplayResult:
    p = db.get(PolicyRecord, policy_id)
    if p is None:
        raise HTTPException(status_code=404, detail="policy not found")
    try:
        compiled = compile_policy_yaml(p.yaml_source)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"stored policy no longer compiles: {e}") from e

    since = datetime.now(UTC) - _REPLAY_WINDOWS[window]
    rows = db.execute(
        select(Action, Decision)
        .join(Decision, Decision.action_id == Action.id)
        .where(Action.action_type == p.action_type, Action.created_at >= since)
        .order_by(Action.created_at.desc())
        .limit(limit)
    ).all()

    total = len(rows)
    same = 0
    would_tighten = 0
    would_loosen = 0
    divergences: list[ReplayDivergence] = []
    for action, recorded in rows:
        replayed = decision_engine.decide(compiled, action.payload, action_type=p.action_type)
        if replayed.decision == recorded.decision:
            same += 1
            continue
        if _TIGHTEN_ORDER[replayed.decision] > _TIGHTEN_ORDER[recorded.decision]:
            would_tighten += 1
        else:
            would_loosen += 1
        divergences.append(ReplayDivergence(
            action_id=action.id,
            created_at=action.created_at,
            from_decision=recorded.decision,  # type: ignore[arg-type]
            to_decision=replayed.decision,  # type: ignore[arg-type]
            to_reasons=replayed.reasons,
        ))
    divergences = divergences[:100]
    return PolicyReplayResult(
        window=window, total=total, same=same, differ=total - same,
        would_tighten=would_tighten, would_loosen=would_loosen,
        divergences=divergences,
    )


def _deactivate_others(db: Session, action_type: str, *, except_id: str) -> None:
    rows = db.execute(
        select(PolicyRecord)
        .where(PolicyRecord.action_type == action_type, PolicyRecord.is_active.is_(True), PolicyRecord.id != except_id)
    ).scalars().all()
    now = datetime.now(UTC)
    for r in rows:
        r.is_active = False
        r.deactivated_at = now
