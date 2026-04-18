from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import auth, evidence, registry, webhooks
from ..config import get_settings
from ..db import get_db
from ..engines import decision as decision_engine
from ..engines.policy import Policy, load_policy
from ..models import Action, Decision, ReviewItem, ThreatAssessmentRow
from ..schemas import DecisionOut, EvaluateRequest, EvidenceBundle, ThreatSignalOut
from ..threats import assess as assess_threats

router = APIRouter(prefix="/v1", tags=["actions"])


@lru_cache
def _policy() -> Policy:
    return load_policy(get_settings().resolved_policy_path)


@router.post("/actions/evaluate", response_model=DecisionOut)
def evaluate_action(
    body: EvaluateRequest,
    background_tasks: BackgroundTasks,
    dry_run: bool = Query(default=False, description="Return decision without persisting"),
    db: Session = Depends(get_db),
    principal: auth.Principal = Depends(auth.require_any_scope),
) -> DecisionOut:
    if not (set(principal.scopes) & {"*", body.action_type}):
        raise HTTPException(status_code=403, detail=f"scope '{body.action_type}' not granted")
    if body.action_type not in registry.LIVE_ACTION_TYPES:
        spec = registry.get(body.action_type)
        if spec is not None and spec.status == "planned":
            raise HTTPException(status_code=501, detail=f"action_type '{body.action_type}' is planned but not live yet")
        raise HTTPException(status_code=400, detail=f"unknown action_type: {body.action_type}")

    policy = _policy()

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
        dec = decision_engine.decide(policy, body.payload)
        return DecisionOut(
            action_id="dry-run",
            decision=dec.decision,
            reasons=dec.reasons,
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
            threat_level=threat_assessment.level,
            threats=threats_out,
        )

    action = Action(action_type=body.action_type, status="received", payload=body.payload)
    db.add(action)
    db.flush()

    evidence.append(db, action_id=action.id, event_type="action.received", payload={
        "action_type": body.action_type,
        "payload": body.payload,
    })

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
            ))
        evidence.append(db, action_id=action.id, event_type="threat.detected", payload={
            "level": threat_assessment.level,
            "signals": [
                {"detector_id": s.detector_id, "owasp_ref": s.owasp_ref, "level": s.level, "message": s.message}
                for s in threat_assessment.signals
            ],
        })

    if threat_assessment.is_blocking:
        # Short-circuit: deny before policy/risk runs.
        reasons = [f"threat-{s.detector_id}" for s in threat_assessment.signals if s.level == "critical"]
        db.add(Decision(
            action_id=action.id,
            decision="deny",
            policy_hits=[],
            risk_score=0,
            risk_breakdown=[],
            policy_version="threat-pipeline",
        ))
        evidence.append(db, action_id=action.id, event_type="decision.made", payload={
            "decision": "deny", "reasons": reasons, "policy_version": "threat-pipeline",
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

    dec = decision_engine.decide(policy, body.payload)
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

    db.add(Decision(
        action_id=action.id,
        decision=dec.decision,
        policy_hits=[{"rule_id": h.rule_id, "action": h.action, "reason": h.reason} for h in dec.hits],
        risk_score=dec.risk_score,
        risk_breakdown=dec.risk_breakdown,
        policy_version=dec.policy_version,
    ))

    evidence.append(db, action_id=action.id, event_type="decision.made", payload={
        "decision": dec.decision,
        "reasons": dec.reasons,
        "risk_score": dec.risk_score,
        "policy_version": dec.policy_version,
    })

    if dec.decision == "allow":
        action.status = "allowed"
    elif dec.decision == "deny":
        action.status = "denied"
    else:
        action.status = "pending_review"
        db.add(ReviewItem(action_id=action.id, status="pending"))

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


@router.get("/decisions/{action_id}", response_model=DecisionOut)
def get_decision(
    action_id: str,
    db: Session = Depends(get_db),
    _: auth.Principal = Depends(auth.require_any_scope),
) -> DecisionOut:
    action = db.get(Action, action_id)
    if action is None or action.decision is None:
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
) -> EvidenceBundle:
    try:
        data = evidence.bundle(db, action_id)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    evidence.append(db, action_id=action_id, event_type="bundle.exported", payload={
        "bundle_hash": data["bundle_hash"],
        "exported_at": data["exported_at"].isoformat(),
    })
    db.commit()
    # re-fetch bundle tip after append so chain stays consistent for client
    final = evidence.bundle(db, action_id)
    final["exported_at"] = datetime.now(UTC)
    return EvidenceBundle(**final)
