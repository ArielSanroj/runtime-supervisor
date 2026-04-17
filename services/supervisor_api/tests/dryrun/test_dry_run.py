"""Dry-run tests: evaluate decisions without persisting actions/decisions/evidence.

Each test verifies (a) the decision matches what the live path would return and
(b) no rows are written to the DB.
"""
from __future__ import annotations

from typing import Any


def _count_all(client) -> dict[str, int]:
    from sqlalchemy import func, select
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import Action, Decision, EvidenceEvent, ReviewItem

    db = SessionLocal()
    try:
        return {
            "actions": db.execute(select(func.count()).select_from(Action)).scalar_one(),
            "decisions": db.execute(select(func.count()).select_from(Decision)).scalar_one(),
            "reviews": db.execute(select(func.count()).select_from(ReviewItem)).scalar_one(),
            "events": db.execute(select(func.count()).select_from(EvidenceEvent)).scalar_one(),
        }
    finally:
        db.close()


def _dry(client, payload: dict[str, Any]) -> dict[str, Any]:
    r = client.post("/v1/actions/evaluate?dry_run=true", json={"action_type": "refund", "payload": payload})
    assert r.status_code == 200, r.text
    return r.json()


def test_dry_run_allow_does_not_persist(client):
    before = _count_all(client)
    out = _dry(client, {"amount": 50, "customer_id": "d1", "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"})
    assert out["decision"] == "allow"
    assert out["action_id"] == "dry-run"
    after = _count_all(client)
    assert before == after


def test_dry_run_review_does_not_persist(client):
    before = _count_all(client)
    out = _dry(client, {"amount": 1200, "customer_id": "d2", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"})
    assert out["decision"] == "review"
    assert out["risk_score"] == 50
    after = _count_all(client)
    assert before == after


def test_dry_run_deny_does_not_persist(client):
    before = _count_all(client)
    out = _dry(client, {"amount": 20000, "customer_id": "d3", "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"})
    assert out["decision"] == "deny"
    assert "amount-exceeds-hard-cap" in out["reasons"]
    after = _count_all(client)
    assert before == after


def test_dry_run_matches_live_decision(client):
    payload = {"amount": 200, "customer_id": "d4", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "fraud_dispute"}
    dry = _dry(client, payload)
    live = client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": payload}).json()
    assert dry["decision"] == live["decision"]
    assert dry["reasons"] == live["reasons"]
    assert dry["risk_score"] == live["risk_score"]
    assert dry["policy_version"] == live["policy_version"]


def test_dry_run_default_off_persists(client):
    before = _count_all(client)["actions"]
    client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": {"amount": 50, "customer_id": "d5", "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"}})
    after = _count_all(client)["actions"]
    assert after == before + 1
