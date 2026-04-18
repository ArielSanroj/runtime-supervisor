from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import AdminEvent

router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(auth.require_admin)])


class AdminEventOut(BaseModel):
    id: int
    actor: str
    action: str
    target_type: str
    target_id: str
    details: dict[str, Any]
    ip_address: str | None
    created_at: datetime


@router.get("/events", response_model=list[AdminEventOut])
def list_admin_events(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None),
    target_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[AdminEventOut]:
    q = select(AdminEvent).order_by(AdminEvent.created_at.desc()).limit(limit)
    if action:
        q = q.where(AdminEvent.action == action)
    if target_type:
        q = q.where(AdminEvent.target_type == target_type)
    rows = db.execute(q).scalars().all()
    return [
        AdminEventOut(
            id=r.id,
            actor=r.actor,
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            details=r.details or {},
            ip_address=r.ip_address,
            created_at=r.created_at,
        )
        for r in rows
    ]
