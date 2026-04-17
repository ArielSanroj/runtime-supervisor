from __future__ import annotations

from typing import Any


def _evaluate(client, payload: dict[str, Any]) -> dict[str, Any]:
    r = client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": payload})
    assert r.status_code == 200, r.text
    return r.json()


def test_benign_refund_is_allowed(client):
    out = _evaluate(client, {"amount": 50, "currency": "USD", "customer_id": "c1", "customer_age_days": 730, "refund_velocity_24h": 0, "reason": "defective"})
    assert out["decision"] == "allow"
    assert out["risk_score"] == 0


def test_borderline_goes_to_review(client):
    out = _evaluate(client, {"amount": 1200, "currency": "USD", "customer_id": "c2", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"})
    assert out["decision"] == "review"
    assert out["risk_score"] == 50


def test_fraud_flag_forces_review(client):
    out = _evaluate(client, {"amount": 200, "currency": "USD", "customer_id": "c3", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "fraud_dispute"})
    assert out["decision"] == "review"
    assert "fraud-dispute-requires-human" in out["reasons"]


def test_hard_cap_denies(client):
    out = _evaluate(client, {"amount": 15000, "currency": "USD", "customer_id": "c4", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"})
    assert out["decision"] == "deny"
    assert "amount-exceeds-hard-cap" in out["reasons"]


def test_invalid_amount_denies(client):
    out = _evaluate(client, {"amount": -50, "currency": "USD", "customer_id": "c5", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"})
    assert out["decision"] == "deny"
    assert "invalid-amount" in out["reasons"]


def test_review_approve_flow_and_evidence_chain(client):
    dec = _evaluate(client, {"amount": 1200, "currency": "USD", "customer_id": "c6", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"})
    action_id = dec["action_id"]

    cases = client.get("/v1/review-cases", params={"status": "pending"}).json()
    case = next(c for c in cases if c["action_id"] == action_id)

    resolve = client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        json={"decision": "approved", "notes": "looks legit"},
        headers={"X-Approver": "ariel@cliocircle.com"},
    )
    assert resolve.status_code == 200, resolve.text
    assert resolve.json()["status"] == "approved"

    bundle = client.get(f"/v1/decisions/{action_id}/evidence").json()
    assert bundle["chain_ok"] is True
    # Expect: action.received, decision.made, review.resolved, bundle.exported
    types = [e["event_type"] for e in bundle["events"]]
    assert types[:3] == ["action.received", "decision.made", "review.resolved"]
    assert bundle["status"] == "approved"
    assert bundle["bundle_signature"]


def test_review_reject_flow(client):
    dec = _evaluate(client, {"amount": 200, "currency": "USD", "customer_id": "c7", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "fraud_dispute"})
    action_id = dec["action_id"]

    cases = client.get("/v1/review-cases").json()
    case = next(c for c in cases if c["action_id"] == action_id)

    r = client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        json={"decision": "rejected", "notes": "confirmed fraud pattern"},
        headers={"X-Approver": "ariel@cliocircle.com"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"

    # Resolving twice must be idempotent-friendly: second attempt returns 409.
    r2 = client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        json={"decision": "rejected"},
    )
    assert r2.status_code == 409


def test_evidence_tamper_detection(client):
    from sqlalchemy import select
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import EvidenceEvent

    dec = _evaluate(client, {"amount": 50, "currency": "USD", "customer_id": "c8", "customer_age_days": 730, "refund_velocity_24h": 0, "reason": "defective"})
    action_id = dec["action_id"]

    db = SessionLocal()
    try:
        ev = db.execute(
            select(EvidenceEvent).where(EvidenceEvent.action_id == action_id).order_by(EvidenceEvent.seq.desc()).limit(1)
        ).scalar_one()
        ev.event_payload = {**ev.event_payload, "tampered": True}
        db.add(ev)
        db.commit()
    finally:
        db.close()

    bundle = client.get(f"/v1/decisions/{action_id}/evidence").json()
    assert bundle["chain_ok"] is False
    assert bundle["broken_at_seq"] is not None
