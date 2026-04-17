from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import evidence, registry
from ..config import get_settings
from ..db import get_db
from ..engines import decision as decision_engine
from ..engines.policy import Policy, load_policy
from ..models import Action, Decision, ReviewItem
from ..schemas import DecisionOut, EvaluateRequest, EvidenceBundle

router = APIRouter(prefix="/v1", tags=["actions"])


@lru_cache
def _policy() -> Policy:
    return load_policy(get_settings().resolved_policy_path)


@router.post("/actions/evaluate", response_model=DecisionOut)
def evaluate_action(
    body: EvaluateRequest,
    dry_run: bool = Query(default=False, description="Return decision without persisting"),
    db: Session = Depends(get_db),
) -> DecisionOut:
    if body.action_type not in registry.LIVE_ACTION_TYPES:
        spec = registry.get(body.action_type)
        if spec is not None and spec.status == "planned":
            raise HTTPException(status_code=501, detail=f"action_type '{body.action_type}' is planned but not live yet")
        raise HTTPException(status_code=400, detail=f"unknown action_type: {body.action_type}")

    policy = _policy()
    if dry_run:
        dec = decision_engine.decide(policy, body.payload)
        return DecisionOut(
            action_id="dry-run",
            decision=dec.decision,
            reasons=dec.reasons,
            risk_score=dec.risk_score,
            policy_version=dec.policy_version,
        )

    action = Action(action_type=body.action_type, status="received", payload=body.payload)
    db.add(action)
    db.flush()

    evidence.append(db, action_id=action.id, event_type="action.received", payload={
        "action_type": body.action_type,
        "payload": body.payload,
    })

    dec = decision_engine.decide(policy, body.payload)

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

    return DecisionOut(
        action_id=action.id,
        decision=dec.decision,
        reasons=dec.reasons,
        risk_score=dec.risk_score,
        policy_version=dec.policy_version,
    )


@router.get("/decisions/{action_id}", response_model=DecisionOut)
def get_decision(action_id: str, db: Session = Depends(get_db)) -> DecisionOut:
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
def get_evidence(action_id: str, db: Session = Depends(get_db)) -> EvidenceBundle:
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
