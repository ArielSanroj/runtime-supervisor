"""Superloop endpoints (SUPERLOOP.md) — run the closed-loop agent over repos and
supervisors, expose the canonical registry + the human approval queue (R1), and
close the loop (ORCHESTRATE→VERIFY→LEARN) over approved decisions.

Tenant-scoped like the rest of the ops API (auth.require_any_scope + tenant_id).
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import auth
from ..db import get_db
from ..superloop import SuperloopFacade

router = APIRouter(prefix="/v1/superloop", tags=["superloop"])

Scope = Literal["repos", "supervisors", "all"]
Verdict = Literal["approved", "rejected", "requires_changes"]


class RunRequest(BaseModel):
    scope: Scope = "all"


class ResolveRequest(BaseModel):
    verdict: Verdict
    notes: str | None = Field(default=None, max_length=2000)


def _facade(db: Session, tenant_id: str) -> SuperloopFacade:
    return SuperloopFacade(db, tenant_id)


@router.post("/run")
def run_loop(
    body: RunRequest,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """OBSERVE→DIAGNOSE→DECIDE over the scope; opens R1 gates; returns cards."""
    return _facade(db, tenant_id).run(body.scope)


@router.get("/registry")
def get_registry(
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """Registro Canónico — current state per business unit (R4)."""
    return {"products": _facade(db, tenant_id).registry()}


@router.get("/queue")
def get_queue(
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """Pending Level >= 3 decisions awaiting human approval (R1)."""
    return {"queue": _facade(db, tenant_id).cola_hitl()}


@router.post("/decisions/{decision_id}/resolve")
def resolve_decision(
    decision_id: str,
    body: ResolveRequest,
    x_approver: str = Header(default="anonymous", alias="X-Approver"),
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """Record a human verdict (R1). Mirrors onto the linked review item."""
    try:
        return _facade(db, tenant_id).aprobar(decision_id, x_approver, body.verdict)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/resume")
def resume(
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    """ORCHESTRATE→VERIFY→LEARN over approved (and Level<3) decisions (R8)."""
    return {"closed": _facade(db, tenant_id).resume_aprobados()}


@router.get("/runs")
def list_runs(
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    return {"runs": _facade(db, tenant_id).runs()}


@router.get("/runs/{run_id}")
def run_detail(
    run_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict[str, Any]:
    cycles = _facade(db, tenant_id).run_detail(run_id)
    if not cycles:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run_id": run_id, "cycles": cycles}
