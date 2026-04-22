from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, auth, execution
from ..db import get_db
from ..models import ActionExecution, Integration
from ..schemas import (
    ActionExecutionOut,
    ExecuteConfigRequest,
    IntegrationCreate,
    IntegrationCreated,
    IntegrationOut,
)

router = APIRouter(prefix="/v1/integrations", tags=["integrations"], dependencies=[Depends(auth.require_admin)])


def _to_out(i: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=i.id,
        name=i.name,
        scopes=i.scopes or [],
        active=i.active,
        created_at=i.created_at,
        revoked_at=i.revoked_at,
        execute_url=i.execute_url,
        execute_method=i.execute_method or "POST",
        tenant_id=i.tenant_id,
    )


@router.post("", response_model=IntegrationCreated, status_code=201)
def create_integration(body: IntegrationCreate, db: Session = Depends(get_db)) -> IntegrationCreated:
    secret = auth.generate_secret()

    # Resolve tenant: explicit assignment wins; otherwise fall through to
    # the "default" tenant so post-migration installs keep working.
    tenant_id = body.tenant_id
    if tenant_id is None:
        from ..auth import _default_tenant_id

        tenant_id = _default_tenant_id(db)
    else:
        from ..models import Tenant

        if db.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=400, detail=f"unknown tenant_id: {tenant_id}")

    integration = Integration(
        name=body.name,
        shared_secret=secret,
        scopes=body.scopes,
        active=True,
        tenant_id=tenant_id,
    )
    db.add(integration)
    try:
        db.commit()
    except Exception as e:  # unique(name) collision
        db.rollback()
        raise HTTPException(status_code=409, detail=f"integration name conflict: {e}") from e
    db.refresh(integration)
    audit.record(actor="admin", action="integration.create", target_type="integration",
                 target_id=integration.id, details={"name": integration.name, "scopes": list(integration.scopes or [])})
    return IntegrationCreated(**_to_out(integration).model_dump(), shared_secret=secret)


@router.get("", response_model=list[IntegrationOut])
def list_integrations(db: Session = Depends(get_db)) -> list[IntegrationOut]:
    items = db.execute(select(Integration).order_by(Integration.created_at.desc())).scalars().all()
    return [_to_out(i) for i in items]


@router.get("/{integration_id}", response_model=IntegrationOut)
def get_integration(integration_id: str, db: Session = Depends(get_db)) -> IntegrationOut:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(status_code=404, detail="integration not found")
    return _to_out(i)


@router.post("/{integration_id}/rotate-secret", response_model=IntegrationCreated)
def rotate_secret(integration_id: str, db: Session = Depends(get_db)) -> IntegrationCreated:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(status_code=404, detail="integration not found")
    new_secret = auth.generate_secret()
    i.shared_secret = new_secret
    db.commit()
    db.refresh(i)
    audit.record(actor="admin", action="integration.rotate", target_type="integration", target_id=i.id, details={})
    return IntegrationCreated(**_to_out(i).model_dump(), shared_secret=new_secret)


@router.put("/{integration_id}/execute-config", response_model=IntegrationOut)
def set_execute_config(
    integration_id: str,
    body: ExecuteConfigRequest,
    db: Session = Depends(get_db),
) -> IntegrationOut:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(status_code=404, detail="integration not found")
    i.execute_url = body.url
    i.execute_method = body.method
    db.commit()
    db.refresh(i)
    audit.record(actor="admin", action="integration.execute_config", target_type="integration",
                 target_id=i.id, details={"url": body.url, "method": body.method})
    return _to_out(i)


@router.post("/{integration_id}/revoke", response_model=IntegrationOut)
def revoke(integration_id: str, db: Session = Depends(get_db)) -> IntegrationOut:
    i = db.get(Integration, integration_id)
    if i is None:
        raise HTTPException(status_code=404, detail="integration not found")
    i.active = False
    i.revoked_at = datetime.now(UTC)
    db.commit()
    db.refresh(i)
    audit.record(actor="admin", action="integration.revoke", target_type="integration", target_id=i.id, details={})
    return _to_out(i)


@router.get("/{integration_id}/executions", response_model=list[ActionExecutionOut])
def list_executions(
    integration_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[ActionExecutionOut]:
    if db.get(Integration, integration_id) is None:
        raise HTTPException(status_code=404, detail="integration not found")
    rows = db.execute(
        select(ActionExecution)
        .where(ActionExecution.integration_id == integration_id)
        .order_by(ActionExecution.queued_at.desc())
        .limit(limit)
    ).scalars().all()
    return [ActionExecutionOut(**execution.build_execution_out(r)) for r in rows]
