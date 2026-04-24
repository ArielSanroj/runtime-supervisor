"""Contract: GET /v1/actions/recent feeds the dashboard's recent-blocks card."""
from __future__ import annotations

_CLEAN = {
    "amount": 50, "customer_id": "c-clean", "currency": "USD",
    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective",
}
_HARDCAP = {**_CLEAN, "amount": 20000}


def test_recent_empty_when_no_actions(client):
    r = client.get("/v1/actions/recent?decision=deny")
    assert r.status_code == 200
    assert r.json() == []


def test_recent_returns_latest_blocks(client):
    # One allow, two denies — recent?decision=deny must return only the 2.
    client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": _CLEAN})
    client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": _HARDCAP})
    client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": _HARDCAP})

    r = client.get("/v1/actions/recent?decision=deny&limit=10")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2
    assert all(row["decision"] == "deny" for row in rows)
    assert all(row["shadow"] is False for row in rows)
    assert "reasons" in rows[0]
    assert "latency_ms" in rows[0]


def test_recent_excludes_shadow_by_default(client):
    client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": _HARDCAP, "shadow": True})
    r = client.get("/v1/actions/recent?decision=deny")
    assert r.status_code == 200
    assert r.json() == []  # shadow actions excluded
    r = client.get("/v1/actions/recent?decision=deny&include_shadow=true")
    # Shadow actions still count in the recent list when explicitly requested;
    # the deny was recorded even though the caller got allow back.
    assert len(r.json()) == 1


def test_recent_rejects_bad_decision(client):
    r = client.get("/v1/actions/recent?decision=bogus")
    assert r.status_code == 422


def test_recent_limit_capped(client):
    r = client.get("/v1/actions/recent?limit=500")
    assert r.status_code == 422  # ge=1, le=50
