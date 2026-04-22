from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..config import get_settings
from ..db import get_db
from ..engines import decision as decision_engine
from ..engines.policy import load_for_action_type
from ..models import ThreatAssessmentRow
from ..schemas import (
    DecisionOut,
    SimulatedAttackOut,
    ThreatAssessmentOut,
    ThreatCatalogEntry,
    ThreatSignalOut,
)
from ..threats import CATALOG as THREAT_CATALOG
from ..threats import assess as assess_threats
from ..threats.catalog import as_dict as threat_as_dict
from ..threats.catalog import get as get_threat_spec

router = APIRouter(prefix="/v1", tags=["threats"])


# ---------- catalog (public) ----------

@router.get("/threats/catalog", response_model=list[ThreatCatalogEntry])
def list_threat_catalog() -> list[ThreatCatalogEntry]:
    return [ThreatCatalogEntry(**threat_as_dict(t)) for t in THREAT_CATALOG]


# ---------- live feed (auth) ----------

@router.get("/threats", response_model=list[ThreatAssessmentOut])
def list_threats(
    limit: int = Query(default=50, ge=1, le=500),
    level: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> list[ThreatAssessmentOut]:
    q = (
        select(ThreatAssessmentRow)
        .where(ThreatAssessmentRow.tenant_id == tenant_id)
        .order_by(ThreatAssessmentRow.created_at.desc())
        .limit(limit)
    )
    if level:
        q = q.where(ThreatAssessmentRow.level == level)
    items = db.execute(q).scalars().all()
    return [
        ThreatAssessmentOut(
            id=t.id, action_id=t.action_id, integration_id=t.integration_id,
            detector_id=t.detector_id, owasp_ref=t.owasp_ref, level=t.level,
            signals=t.signals or [], created_at=t.created_at,
        )
        for t in items
    ]


@router.get("/threats/{threat_id}", response_model=ThreatAssessmentOut)
def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> ThreatAssessmentOut:
    t = db.get(ThreatAssessmentRow, threat_id)
    if t is None or t.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="threat not found")
    return ThreatAssessmentOut(
        id=t.id, action_id=t.action_id, integration_id=t.integration_id,
        detector_id=t.detector_id, owasp_ref=t.owasp_ref, level=t.level,
        signals=t.signals or [], created_at=t.created_at,
    )


# ---------- simulator (public, rate-limited) ----------

_SIM_WINDOW_SECONDS = 1.0
_SIM_MAX_PER_WINDOW = 20
_sim_buckets: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=_SIM_MAX_PER_WINDOW))


def _rate_limit(ip: str) -> None:
    now = time.monotonic()
    bucket = _sim_buckets[ip]
    while bucket and now - bucket[0] > _SIM_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _SIM_MAX_PER_WINDOW:
        raise HTTPException(status_code=429, detail="rate limit exceeded — wait a second and try again")
    bucket.append(now)


@router.post("/simulate/attack", response_model=SimulatedAttackOut)
def simulate_attack(
    request: Request,
    type: str = Query(..., description="Threat catalog id, e.g. prompt-injection"),
) -> SimulatedAttackOut:
    _rate_limit(request.client.host if request.client else "anon")

    spec = get_threat_spec(type)
    if spec is None:
        raise HTTPException(status_code=404, detail=f"unknown threat type: {type}")

    payload = dict(spec.sample_attack)
    threat_assessment = assess_threats(payload, db=None, integration_id="simulator")
    threats_out = [
        ThreatSignalOut(
            detector_id=s.detector_id, owasp_ref=s.owasp_ref, level=s.level,
            message=s.message, evidence=s.evidence,
        )
        for s in threat_assessment.signals
    ]

    if threat_assessment.is_blocking:
        decision = DecisionOut(
            action_id="simulated",
            decision="deny",
            reasons=[f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "critical"],
            risk_score=0,
            policy_version="threat-pipeline",
            threat_level=threat_assessment.level,
            threats=threats_out,
        )
    elif threat_assessment.needs_review:
        decision = DecisionOut(
            action_id="simulated",
            decision="review",
            reasons=[f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "warn"],
            risk_score=0,
            policy_version="threat-pipeline",
            threat_level=threat_assessment.level,
            threats=threats_out,
        )
    else:
        # Threat missed by detectors — fall back to policy/risk for honesty.
        policy = load_for_action_type("refund", get_settings().repo_root)
        dec = decision_engine.decide(policy, payload, action_type="refund")
        decision = DecisionOut(
            action_id="simulated",
            decision=dec.decision,
            reasons=dec.reasons,
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
            threat_level="none",
            threats=[],
        )

    _: Any = None
    return SimulatedAttackOut(threat_id=type, decision=decision, threats=threats_out)
