from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth, evidence, execution, ratelimit, registry, webhooks
from ..config import get_settings
from ..db import get_db
from ..engines import decision as decision_engine
from ..engines.policy import Policy, load_for_action_type_with_db
from ..models import Action, Decision, ReviewItem, ThreatAssessmentRow
from ..schemas import (
    DecisionOut,
    EvaluateRequest,
    EvidenceBundle,
    EvidenceExportResult,
    RecentActionOut,
    ThreatSignalOut,
)
from ..threats import assess as assess_threats

router = APIRouter(prefix="/v1", tags=["actions"])


def _policy(action_type: str, db: Session) -> Policy:
    # DB-managed active policy wins; fall back to packages/policies/*.yaml.
    # No cache: promoting a new policy takes effect on the next evaluate.
    return load_for_action_type_with_db(action_type, db, get_settings().repo_root)


@router.post("/actions/evaluate", response_model=DecisionOut)
def evaluate_action(
    body: EvaluateRequest,
    background_tasks: BackgroundTasks,
    dry_run: bool = Query(default=False, description="Return decision without persisting"),
    db: Session = Depends(get_db),
    principal: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> DecisionOut:
    if not (set(principal.scopes) & {"*", body.action_type}):
        raise HTTPException(status_code=403, detail=f"scope '{body.action_type}' not granted")
    ratelimit.check_and_consume(principal)
    if body.action_type not in registry.LIVE_ACTION_TYPES:
        spec = registry.get(body.action_type)
        if spec is not None and spec.status == "planned":
            raise HTTPException(status_code=501, detail=f"action_type '{body.action_type}' is planned but not live yet")
        raise HTTPException(status_code=400, detail=f"unknown action_type: {body.action_type}")

    policy = _policy(body.action_type, db)

    # Threat pipeline runs first. Critical → deny; warn → review; else continue.
    threat_assessment = assess_threats(body.payload, db=db, integration_id=principal.integration_id)
    threats_out = [
        ThreatSignalOut(
            detector_id=s.detector_id, owasp_ref=s.owasp_ref, level=s.level,
            message=s.message, evidence=s.evidence,
        )
        for s in threat_assessment.signals
    ]

    if dry_run:
        if threat_assessment.is_blocking:
            return DecisionOut(
                action_id="dry-run", decision="deny",
                reasons=[f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "critical"],
                risk_score=0, policy_version="threat-pipeline",
                threat_level=threat_assessment.level, threats=threats_out,
            )
        if threat_assessment.needs_review:
            return DecisionOut(
                action_id="dry-run", decision="review",
                reasons=[f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "warn"],
                risk_score=0, policy_version="threat-pipeline",
                threat_level=threat_assessment.level, threats=threats_out,
            )
        dec = decision_engine.decide(policy, body.payload, action_type=body.action_type)
        return DecisionOut(
            action_id="dry-run",
            decision=dec.decision,
            reasons=dec.reasons,
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
            threat_level=threat_assessment.level,
            threats=threats_out,
        )

    eval_started_at = time.perf_counter()
    action = Action(
        action_type=body.action_type,
        status="received",
        payload=body.payload,
        shadow=body.shadow,
        tenant_id=tenant_id,
    )
    db.add(action)
    db.flush()

    evidence.append(db, action_id=action.id, event_type="action.received", payload={
        "action_type": body.action_type,
        "payload": body.payload,
    })

    # Attach the agent's session context (identity, goal, tools, sources) when
    # the caller supplies it. Separate event so the audit trail distinguishes
    # the action itself from the metadata around it.
    if body.agent_context:
        evidence.append(db, action_id=action.id, event_type="agent.context", payload=body.agent_context)

    # Persist threat assessment rows + evidence event when signals were raised
    if threat_assessment.signals:
        for s in threat_assessment.signals:
            db.add(ThreatAssessmentRow(
                action_id=action.id,
                integration_id=principal.integration_id,
                detector_id=s.detector_id,
                owasp_ref=s.owasp_ref,
                level=s.level,
                signals=[{"message": s.message, "evidence": s.evidence}],
                tenant_id=tenant_id,
            ))
        evidence.append(db, action_id=action.id, event_type="threat.detected", payload={
            "level": threat_assessment.level,
            "signals": [
                {"detector_id": s.detector_id, "owasp_ref": s.owasp_ref, "level": s.level, "message": s.message}
                for s in threat_assessment.signals
            ],
        })

    if threat_assessment.is_blocking:
        from .. import alerting
        # Short-circuit: deny before policy/risk runs.
        reasons = [f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "critical"]
        latency_ms = int((time.perf_counter() - eval_started_at) * 1000)
        db.add(Decision(
            action_id=action.id,
            decision="deny",
            policy_hits=[],
            risk_score=0,
            risk_breakdown=[],
            policy_version="threat-pipeline",
            latency_ms=latency_ms,
            tenant_id=tenant_id,
        ))
        evidence.append(db, action_id=action.id, event_type="decision.made", payload={
            "decision": "deny", "reasons": reasons, "policy_version": "threat-pipeline",
            "shadow": body.shadow,
        })
        # In shadow mode we still record the would-have-denied for metrics
        # but do NOT alert, webhook, or surface deny to the caller.
        if body.shadow:
            action.status = "shadow_deny"
            db.commit()
            return DecisionOut(
                action_id=action.id, decision="allow", reasons=[],
                risk_score=0, policy_version="threat-pipeline",
                threat_level=threat_assessment.level, threats=threats_out,
                shadow_would_have="deny",
            )
        alerting.emit("threat.critical", {
            "action_type": body.action_type,
            "integration_id": principal.integration_id,
            "signals": [{"detector_id": s.detector_id, "owasp_ref": s.owasp_ref} for s in threat_assessment.signals],
        })
        action.status = "denied"
        db.commit()
        background_tasks.add_task(
            webhooks.dispatch, "action.denied",
            {
                "action_id": action.id, "action_type": body.action_type,
                "decision": "deny", "reasons": reasons,
                "threat_level": threat_assessment.level,
            },
        )
        background_tasks.add_task(
            webhooks.dispatch, "threat.detected",
            {
                "action_id": action.id, "level": threat_assessment.level,
                "signals": [
                    {"detector_id": s.detector_id, "owasp_ref": s.owasp_ref, "level": s.level, "message": s.message}
                    for s in threat_assessment.signals
                ],
            },
        )
        return DecisionOut(
            action_id=action.id, decision="deny", reasons=reasons,
            risk_score=0, policy_version="threat-pipeline",
            threat_level=threat_assessment.level, threats=threats_out,
        )

    dec = decision_engine.decide(policy, body.payload, action_type=body.action_type)
    # A warn-level threat escalates decision to review regardless of policy/risk outcome.
    if threat_assessment.needs_review and dec.decision == "allow":
        threat_reasons = [f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "warn"]
        dec = decision_engine.Decision(  # type: ignore[attr-defined]
            decision="review",
            reasons=threat_reasons,
            hits=dec.hits,
            risk_score=dec.risk_score,
            risk_breakdown=dec.risk_breakdown,
            policy_version=dec.policy_version,
        )

    latency_ms = int((time.perf_counter() - eval_started_at) * 1000)
    db.add(Decision(
        action_id=action.id,
        decision=dec.decision,
        policy_hits=[
            {"rule_id": h.rule_id, "action": h.action, "reason": h.reason, "explanation": h.explanation}
            for h in dec.hits
        ],
        risk_score=dec.risk_score,
        risk_breakdown=dec.risk_breakdown,
        policy_version=dec.policy_version,
        latency_ms=latency_ms,
        tenant_id=tenant_id,
    ))

    evidence.append(db, action_id=action.id, event_type="decision.made", payload={
        "decision": dec.decision,
        "reasons": dec.reasons,
        "risk_score": dec.risk_score,
        "policy_version": dec.policy_version,
        "shadow": body.shadow,
    })

    # Shadow mode: record everything for metrics, but don't create a review
    # case, don't execute downstream, don't webhook deny events, and always
    # return "allow" with shadow_would_have populated.
    if body.shadow:
        action.status = f"shadow_{dec.decision}"
        db.commit()
        if threat_assessment.signals:
            background_tasks.add_task(
                webhooks.dispatch, "threat.detected",
                {
                    "action_id": action.id, "level": threat_assessment.level,
                    "signals": [
                        {"detector_id": s.detector_id, "owasp_ref": s.owasp_ref, "level": s.level, "message": s.message}
                        for s in threat_assessment.signals
                    ],
                    "shadow": True,
                },
            )
        return DecisionOut(
            action_id=action.id,
            decision="allow",
            reasons=[],
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
            threat_level=threat_assessment.level,
            threats=threats_out,
            shadow_would_have=dec.decision,  # type: ignore[arg-type]
        )

    if dec.decision == "allow":
        action.status = "allowed"
    elif dec.decision == "deny":
        action.status = "denied"
    else:
        action.status = "pending_review"
        db.add(ReviewItem(action_id=action.id, status="pending", tenant_id=tenant_id))

    db.commit()

    webhook_event = "action.denied" if dec.decision == "deny" else "decision.made"
    background_tasks.add_task(
        webhooks.dispatch,
        webhook_event,
        {
            "action_id": action.id,
            "action_type": body.action_type,
            "decision": dec.decision,
            "reasons": dec.reasons,
            "risk_score": dec.risk_score,
            "policy_version": dec.policy_version,
            "threat_level": threat_assessment.level,
        },
    )
    if dec.decision == "allow":
        background_tasks.add_task(
            execution.execute, action.id,
            triggered_by="allow", integration_id=principal.integration_id,
        )
    if threat_assessment.signals:
        background_tasks.add_task(
            webhooks.dispatch, "threat.detected",
            {
                "action_id": action.id, "level": threat_assessment.level,
                "signals": [
                    {"detector_id": s.detector_id, "owasp_ref": s.owasp_ref, "level": s.level, "message": s.message}
                    for s in threat_assessment.signals
                ],
            },
        )

    return DecisionOut(
        action_id=action.id,
        decision=dec.decision,
        reasons=dec.reasons,
        risk_score=dec.risk_score,
        policy_version=dec.policy_version,
        threat_level=threat_assessment.level,
        threats=threats_out,
    )


@router.get("/actions/{action_id}/execution")
def get_action_execution(
    action_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> dict:
    from ..models import ActionExecution

    # Scope by parent action's tenant to prevent cross-tenant reads even if a
    # caller guesses another tenant's action_id. 404 (not 403) so we don't
    # leak that the ID exists.
    parent_tenant = db.execute(
        select(Action.tenant_id).where(Action.id == action_id)
    ).scalar_one_or_none()
    if parent_tenant is None or parent_tenant != tenant_id:
        raise HTTPException(status_code=404, detail="no execution recorded for this action")

    row = db.query(ActionExecution).filter_by(action_id=action_id).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="no execution recorded for this action")
    return execution.build_execution_out(row)


@router.post("/actions/{action_id}/execution/retry")
def retry_action_execution(
    action_id: str,
    _: auth.Principal = Depends(auth.require_admin),
) -> dict:
    try:
        return execution.retry_dead_or_failed(action_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/decisions/{action_id}", response_model=DecisionOut)
def get_decision(
    action_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> DecisionOut:
    action = db.get(Action, action_id)
    if action is None or action.decision is None or action.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="decision not found")
    d = action.decision
    reasons = [h.get("reason") for h in d.policy_hits] or [
        "passes-policy-and-risk" if d.decision == "allow"
        else (f"risk-score-{d.risk_score}" if d.decision == "review" else "denied")
    ]
    return DecisionOut(
        action_id=action.id,
        decision=d.decision,  # type: ignore[arg-type]
        reasons=[r for r in reasons if r],
        risk_score=d.risk_score,
        policy_version=d.policy_version,
    )


@router.get("/decisions/{action_id}/evidence", response_model=EvidenceBundle)
def get_evidence(
    action_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> EvidenceBundle:
    parent_tenant = db.execute(
        select(Action.tenant_id).where(Action.id == action_id)
    ).scalar_one_or_none()
    if parent_tenant is None or parent_tenant != tenant_id:
        raise HTTPException(status_code=404, detail="evidence not found")

    try:
        data = evidence.bundle(db, action_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    evidence.append(db, action_id=action_id, event_type="bundle.exported", payload={
        "bundle_hash": data["bundle_hash"],
        "exported_at": data["exported_at"].isoformat(),
    }, tenant_id=tenant_id)
    db.commit()
    # re-fetch bundle tip after append so chain stays consistent for client
    final = evidence.bundle(db, action_id)
    final["exported_at"] = datetime.now(UTC)
    return EvidenceBundle(**final)


@router.get("/actions/recent", response_model=list[RecentActionOut])
def list_recent_actions(
    decision: str | None = Query(default=None, pattern="^(allow|deny|review)$"),
    limit: int = Query(default=20, ge=1, le=50),
    include_shadow: bool = Query(default=False),
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> list[RecentActionOut]:
    """Most recent actions with their decisions. Feeds the dashboard's
    'Recent blocks' card. `decision=deny` gives blocks only; omit to get
    all. By default excludes shadow-mode calls so operators see real
    enforcement events."""
    q = (
        select(Decision, Action)
        .join(Action, Action.id == Decision.action_id)
        .where(Action.tenant_id == tenant_id)
    )
    if decision:
        q = q.where(Decision.decision == decision)
    if not include_shadow:
        q = q.where(Action.shadow.is_(False))
    q = q.order_by(Action.created_at.desc()).limit(limit)

    rows = db.execute(q).all()
    out: list[RecentActionOut] = []
    for dec, action in rows:
        reasons = [h.get("reason") for h in (dec.policy_hits or [])] or ([
            "passes-policy-and-risk" if dec.decision == "allow"
            else (f"risk-score-{dec.risk_score}" if dec.decision == "review" else "denied")
        ])
        out.append(RecentActionOut(
            action_id=action.id,
            action_type=action.action_type,
            decision=dec.decision,  # type: ignore[arg-type]
            reasons=[r for r in reasons if r],
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
            created_at=action.created_at,
            latency_ms=dec.latency_ms,
            shadow=action.shadow,
        ))
    return out


@router.post("/decisions/{action_id}/evidence/export", response_model=EvidenceExportResult)
def export_evidence_to_blob(
    action_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
    tenant_id: str = Depends(auth.require_tenant_id),
) -> EvidenceExportResult:
    parent_tenant = db.execute(
        select(Action.tenant_id).where(Action.id == action_id)
    ).scalar_one_or_none()
    if parent_tenant is None or parent_tenant != tenant_id:
        raise HTTPException(status_code=404, detail="evidence not found")
    """Serialize the action's evidence bundle to the configured blob storage
    (local FS or S3) and return the durable URL. Useful for compliance
    retention — the DB can be pruned but the signed bundle remains recoverable.
    """
    import json
    from datetime import date

    from .. import storage

    try:
        data = evidence.bundle(db, action_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    day = date.today().isoformat()
    key = f"{day}/{action_id}.json"
    body = json.dumps(data, default=str).encode()
    url = storage.get_backend().put(key, body)

    evidence.append(db, action_id=action_id, event_type="bundle.exported_to_blob", payload={
        "url": url, "bundle_hash": data["bundle_hash"],
    }, tenant_id=tenant_id)
    db.commit()

    return EvidenceExportResult(
        action_id=action_id,
        key=key,
        url=url,
        bundle_hash=data["bundle_hash"],
        bundle_signature=data["bundle_signature"],
        exported_at=data["exported_at"],
        size_bytes=len(body),
    )
