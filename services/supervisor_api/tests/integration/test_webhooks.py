"""Webhook subscription CRUD + dispatch on decision.made / review.resolved.

Outbound HTTP is monkey-patched to capture the call without needing a real
receiver; this exercises the dispatcher + signature computation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading

import httpx
import pytest

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


@pytest.fixture()
def captured(monkeypatch):
    """Replace httpx.post with a recorder; return the list of captured calls."""
    calls: list[dict] = []
    lock = threading.Lock()

    def fake_post(url, *, content=None, headers=None, timeout=None):
        with lock:
            calls.append({"url": url, "content": content, "headers": dict(headers or {})})
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr("supervisor_api.webhooks.httpx.post", fake_post)
    return calls


def _register_webhook(client, url: str, events: list[str]) -> dict:
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": f"wh-{url[-6:]}", "scopes": ["*"]}).json()
    r = client.post(
        f"/v1/integrations/{integ['id']}/webhooks",
        headers=ADMIN_HEADERS,
        json={"url": url, "events": events},
    )
    assert r.status_code == 201, r.text
    return {"integration": integ, "sub": r.json()}


def test_webhook_fires_on_allow_decision(client, captured):
    _register_webhook(client, "https://example.test/hook1", ["decision.made"])

    r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r.status_code == 200

    assert len(captured) == 1
    call = captured[0]
    assert call["url"] == "https://example.test/hook1"
    body = json.loads(call["content"])
    assert body["event"] == "decision.made"
    assert body["data"]["decision"] == "allow"
    assert call["headers"]["x-supervisor-event"] == "decision.made"
    # Signature header is `sha256=<hex>`
    sig_header = call["headers"]["x-supervisor-signature"]
    assert sig_header.startswith("sha256=")


def test_webhook_signature_is_verifiable(client, captured):
    _register_webhook(client, "https://example.test/sig", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c2", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"},
    })
    call = captured[0]
    got_sig = call["headers"]["x-supervisor-signature"].removeprefix("sha256=")
    expected = hmac.new(b"test-webhook-secret", call["content"], hashlib.sha256).hexdigest()
    assert hmac.compare_digest(got_sig, expected)


def test_deny_fires_action_denied_event(client, captured):
    _register_webhook(client, "https://example.test/denied", ["action.denied"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 15000, "customer_id": "c3", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert any(c["url"] == "https://example.test/denied" for c in captured)
    for c in captured:
        body = json.loads(c["content"])
        assert body["event"] == "action.denied"


def test_subscription_not_fired_when_event_not_subscribed(client, captured):
    # subscribed only to review.resolved; firing an allow should not hit this sub
    _register_webhook(client, "https://example.test/review-only", ["review.resolved"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c4", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert all(c["url"] != "https://example.test/review-only" for c in captured)


def test_review_resolve_fires_webhook(client, captured):
    _register_webhook(client, "https://example.test/review", ["review.resolved"])
    dec = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 1200, "customer_id": "c5", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"},
    }).json()
    cases = client.get("/v1/review-cases", params={"status": "pending"}).json()
    case = next(c for c in cases if c["action_id"] == dec["action_id"])

    r = client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        json={"decision": "approved", "notes": "ok"},
        headers={"X-Approver": "ariel@cliocircle.com"},
    )
    assert r.status_code == 200

    review_hits = [c for c in captured if c["url"] == "https://example.test/review"]
    assert len(review_hits) == 1
    body = json.loads(review_hits[0]["content"])
    assert body["event"] == "review.resolved"
    assert body["data"]["status"] == "approved"
    assert body["data"]["approver"] == "ariel@cliocircle.com"


def test_delivery_is_recorded(client, captured):
    fixture = _register_webhook(client, "https://example.test/delivered", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c6", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"},
    })
    integ_id = fixture["integration"]["id"]
    sub_id = fixture["sub"]["id"]
    deliveries = client.get(f"/v1/integrations/{integ_id}/webhooks/{sub_id}/deliveries", headers=ADMIN_HEADERS).json()
    assert len(deliveries) == 1
    assert deliveries[0]["status_code"] == 200
    assert deliveries[0]["error"] is None
    assert deliveries[0]["delivered_at"] is not None


def test_subscription_crud(client):
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "crud-app", "scopes": ["*"]}).json()
    # create
    r = client.post(
        f"/v1/integrations/{integ['id']}/webhooks",
        headers=ADMIN_HEADERS,
        json={"url": "https://example.test/crud", "events": ["decision.made"]},
    )
    assert r.status_code == 201
    sub_id = r.json()["id"]
    # list
    lst = client.get(f"/v1/integrations/{integ['id']}/webhooks", headers=ADMIN_HEADERS).json()
    assert any(s["id"] == sub_id for s in lst)
    # delete
    d = client.delete(f"/v1/integrations/{integ['id']}/webhooks/{sub_id}", headers=ADMIN_HEADERS)
    assert d.status_code == 204
    lst2 = client.get(f"/v1/integrations/{integ['id']}/webhooks", headers=ADMIN_HEADERS).json()
    assert all(s["id"] != sub_id for s in lst2)
