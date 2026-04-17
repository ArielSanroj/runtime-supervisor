from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import evidence
from ..db import get_db
from ..models import Action, ReviewItem
from ..schemas import ReviewItemOut, ReviewResolveRequest

router = APIRouter(prefix="/v1", tags=["review"])


def _to_out(item: ReviewItem, action: Action) -> ReviewItemOut:
    d = action.decision
    return ReviewItemOut(
        id=item.id,
        action_id=item.action_id,
        status=item.status,  # type: ignore[arg-type]
        action_payload=action.payload,
        action_type=action.action_type,
        risk_score=d.risk_score if d else 0,
        policy_hits=d.policy_hits if d else [],
        created_at=item.created_at,
        resolved_at=item.resolved_at,
        approver=item.approver,
        approver_notes=item.approver_notes,
    )


@router.get("/review-cases", response_model=list[ReviewItemOut])
def list_reviews(
    status: Literal["pending", "approved", "rejected"] | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[ReviewItemOut]:
    q = select(ReviewItem).order_by(ReviewItem.created_at.desc())
    if status:
        q = q.where(ReviewItem.status == status)
    items = db.execute(q).scalars().all()
    out = []
    for item in items:
        action = db.get(Action, item.action_id)
        if action is not None:
            out.append(_to_out(item, action))
    return out


@router.get("/review-cases/{review_id}", response_model=ReviewItemOut)
def get_review(review_id: str, db: Session = Depends(get_db)) -> ReviewItemOut:
    item = db.get(ReviewItem, review_id)
    if item is None:
        raise HTTPException(status_code=404, detail="review not found")
    action = db.get(Action, item.action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return _to_out(item, action)


@router.post("/review-cases/{review_id}/resolve", response_model=ReviewItemOut)
def resolve_review(
    review_id: str,
    body: ReviewResolveRequest,
    x_approver: str = Header(default="anonymous", alias="X-Approver"),
    db: Session = Depends(get_db),
) -> ReviewItemOut:
    item = db.get(ReviewItem, review_id)
    if item is None:
        raise HTTPException(status_code=404, detail="review not found")
    if item.status != "pending":
        raise HTTPException(status_code=409, detail=f"review already {item.status}")

    action = db.get(Action, item.action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")

    item.status = body.decision
    item.approver = x_approver
    item.approver_notes = body.notes
    item.resolved_at = datetime.now(UTC)
    action.status = "approved" if body.decision == "approved" else "rejected"

    evidence.append(db, action_id=action.id, event_type="review.resolved", payload={
        "decision": body.decision,
        "approver": x_approver,
        "notes": body.notes,
    })

    db.commit()
    return _to_out(item, action)
