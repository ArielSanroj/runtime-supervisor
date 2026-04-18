"""Tenant CRUD (Phase T scaffold).

Creates the tenant container but does NOT yet enforce per-tenant row
filtering in queries or JWT audience claims. Full multi-tenant
enforcement is a follow-up refactor. Today this just lets admin
register named tenants and assign integrations to them.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..models import Tenant

router = APIRouter(prefix="/v1/tenants", tags=["tenants"], dependencies=[Depends(auth.require_admin)])


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class TenantOut(BaseModel):
    id: str
    name: str
    active: bool
    created_at: datetime


@router.post("", response_model=TenantOut, status_code=201)
def create_tenant(body: TenantCreate, db: Session = Depends(get_db)) -> TenantOut:
    t = Tenant(name=body.name, active=True)
    db.add(t)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"tenant conflict: {e}") from e
    db.refresh(t)
    return TenantOut(id=t.id, name=t.name, active=t.active, created_at=t.created_at)


@router.get("", response_model=list[TenantOut])
def list_tenants(db: Session = Depends(get_db)) -> list[TenantOut]:
    rows = db.execute(select(Tenant).order_by(Tenant.created_at.desc())).scalars().all()
    return [TenantOut(id=t.id, name=t.name, active=t.active, created_at=t.created_at) for t in rows]


@router.get("/{tenant_id}", response_model=TenantOut)
def get_tenant(tenant_id: str, db: Session = Depends(get_db)) -> TenantOut:
    t = db.get(Tenant, tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return TenantOut(id=t.id, name=t.name, active=t.active, created_at=t.created_at)
