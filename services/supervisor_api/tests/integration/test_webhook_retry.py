"""Async retry queue behavior: failed deliveries persist, worker retries with backoff."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


def _register(client, url: str, events: list[str]) -> dict:
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": f"rq-{url[-8:]}", "scopes": ["*"]}).json()
    r = client.post(f"/v1/integrations/{integ['id']}/webhooks", headers=ADMIN_HEADERS,
                    json={"url": url, "events": events})
    assert r.status_code == 201
    return {"integ": integ, "sub": r.json()}


def test_failed_first_attempt_goes_pending_with_next_retry(client, monkeypatch):
    def failing_post(url, *, content=None, headers=None, timeout=None):
        return httpx.Response(500, request=httpx.Request("POST", url), text="boom")
    monkeypatch.setattr("supervisor_api.webhooks.httpx.post", failing_post)

    _register(client, "https://downstream.example/fail", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })

    from supervisor_api.db import SessionLocal
    from supervisor_api.models import WebhookDelivery
    db = SessionLocal()
    try:
        d = db.query(WebhookDelivery).one()
        assert d.state == "pending"
        assert d.attempts == 1
        assert d.next_retry_at is not None
        assert d.status_code == 500
    finally:
        db.close()


def test_worker_retries_and_succeeds(client, monkeypatch):
    attempts = {"n": 0}

    def flaky_post(url, *, content=None, headers=None, timeout=None):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(502, request=httpx.Request("POST", url))
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr("supervisor_api.webhooks.httpx.post", flaky_post)
    _register(client, "https://downstream.example/flaky", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })

    # Force next_retry_at into the past so the worker picks it up immediately
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import WebhookDelivery
    db = SessionLocal()
    try:
        d = db.query(WebhookDelivery).one()
        d.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    from supervisor_api.webhooks import retry_due_deliveries
    counts = retry_due_deliveries()
    assert counts["retried"] == 1
    assert counts["succeeded"] == 1

    db = SessionLocal()
    try:
        d = db.query(WebhookDelivery).one()
        assert d.state == "success"
        assert d.attempts == 2
        assert d.next_retry_at is None
        assert d.delivered_at is not None
    finally:
        db.close()


def test_exhausting_attempts_marks_dead(client, monkeypatch):
    monkeypatch.setattr(
        "supervisor_api.webhooks.httpx.post",
        lambda url, **kw: httpx.Response(500, request=httpx.Request("POST", url)),
    )
    _register(client, "https://downstream.example/dead", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })

    from supervisor_api.db import SessionLocal
    from supervisor_api.models import WebhookDelivery
    from supervisor_api.webhooks import MAX_ATTEMPTS, retry_due_deliveries

    # Force retries until MAX_ATTEMPTS, each time backdating next_retry_at
    for _ in range(MAX_ATTEMPTS):
        db = SessionLocal()
        try:
            d = db.query(WebhookDelivery).one()
            if d.state != "pending":
                break
            d.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()
        finally:
            db.close()
        retry_due_deliveries()

    db = SessionLocal()
    try:
        d = db.query(WebhookDelivery).one()
        assert d.state == "dead"
        assert d.attempts == MAX_ATTEMPTS
        assert d.next_retry_at is None
    finally:
        db.close()


def test_worker_ignores_not_due_deliveries(client, monkeypatch):
    monkeypatch.setattr(
        "supervisor_api.webhooks.httpx.post",
        lambda url, **kw: httpx.Response(500, request=httpx.Request("POST", url)),
    )
    _register(client, "https://downstream.example/future", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    # Delivery is now pending with next_retry_at in ~1s from now.
    from supervisor_api.webhooks import retry_due_deliveries
    counts = retry_due_deliveries()
    assert counts["retried"] == 0


def test_success_first_try_never_schedules_retry(client, monkeypatch):
    monkeypatch.setattr(
        "supervisor_api.webhooks.httpx.post",
        lambda url, **kw: httpx.Response(200, request=httpx.Request("POST", url)),
    )
    _register(client, "https://downstream.example/ok", ["decision.made"])
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    from supervisor_api.db import SessionLocal
    from supervisor_api.models import WebhookDelivery
    db = SessionLocal()
    try:
        d = db.query(WebhookDelivery).one()
        assert d.state == "success"
        assert d.next_retry_at is None
        assert d.attempts == 1
    finally:
        db.close()
