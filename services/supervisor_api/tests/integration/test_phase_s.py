"""Phase S: rate limiting, payload size limit, admin audit log."""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


def _make_jwt(app_id: str, secret: str, scopes: list[str]) -> str:
    from supervisor_api.auth import sign_jwt

    return sign_jwt(
        {"sub": app_id, "scopes": scopes,
         "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())},
        secret,
    )


@pytest.fixture()
def auth_on():
    from supervisor_api.config import get_settings
    from supervisor_api.ratelimit import reset

    os.environ["REQUIRE_AUTH"] = "true"
    os.environ["RATE_LIMIT_PER_MINUTE"] = "5"
    get_settings.cache_clear()
    reset()
    yield
    os.environ["REQUIRE_AUTH"] = "false"
    os.environ.pop("RATE_LIMIT_PER_MINUTE", None)
    get_settings.cache_clear()
    reset()


def test_rate_limit_returns_429(client, auth_on):
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS,
                       json={"name": "rl", "scopes": ["*"]}).json()
    token = _make_jwt(integ["id"], integ["shared_secret"], ["*"])
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"action_type": "refund",
               "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                           "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}}

    # 5 calls succeed, 6th is throttled
    for _ in range(5):
        r = client.post("/v1/actions/evaluate", headers=headers, json=payload)
        assert r.status_code == 200, r.text
    r = client.post("/v1/actions/evaluate", headers=headers, json=payload)
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_rate_limit_isolated_per_integration(client, auth_on):
    a = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "a", "scopes": ["*"]}).json()
    b = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "b", "scopes": ["*"]}).json()
    tok_a = _make_jwt(a["id"], a["shared_secret"], ["*"])
    tok_b = _make_jwt(b["id"], b["shared_secret"], ["*"])
    payload = {"action_type": "refund",
               "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                           "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}}
    # Exhaust a's quota
    for _ in range(5):
        client.post("/v1/actions/evaluate", headers={"Authorization": f"Bearer {tok_a}"}, json=payload)
    # b is still fine
    r = client.post("/v1/actions/evaluate", headers={"Authorization": f"Bearer {tok_b}"}, json=payload)
    assert r.status_code == 200


def test_payload_size_limit_returns_413(client):
    big = {"action_type": "refund", "payload": {"blob": "x" * 70000}}
    r = client.post("/v1/actions/evaluate", json=big)
    assert r.status_code == 413
    assert "exceeds" in r.json()["detail"]


def test_admin_events_are_recorded(client):
    client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "audit1", "scopes": ["*"]})

    events = client.get("/v1/admin/events", headers=ADMIN_HEADERS).json()
    assert any(e["action"] == "integration.create" and e["target_type"] == "integration" for e in events)


def test_admin_events_filter_by_action(client):
    i = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "audit2", "scopes": ["*"]}).json()
    client.post(f"/v1/integrations/{i['id']}/revoke", headers=ADMIN_HEADERS)

    events = client.get("/v1/admin/events?action=integration.revoke", headers=ADMIN_HEADERS).json()
    assert all(e["action"] == "integration.revoke" for e in events)
    assert len(events) >= 1


def test_admin_events_require_admin_token(client):
    r = client.get("/v1/admin/events")
    assert r.status_code == 401


def test_policy_promote_emits_audit(client):
    yaml = "name: t\nversion: 1\nrules: []\n"
    p = client.post("/v1/policies", headers=ADMIN_HEADERS,
                    json={"action_type": "refund", "yaml_source": yaml, "promote": False}).json()
    client.post(f"/v1/policies/{p['id']}/promote", headers=ADMIN_HEADERS)
    events = client.get("/v1/admin/events?action=policy.promote", headers=ADMIN_HEADERS).json()
    assert any(e["target_id"] == p["id"] for e in events)
