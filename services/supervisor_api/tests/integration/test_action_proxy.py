"""action_proxy: execution triggered on allow + review.approved, not on deny/reject.

These tests run with REQUIRE_AUTH=true so the principal resolves to a real
integration — otherwise execute() has nothing to look up.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


@pytest.fixture()
def captured(monkeypatch):
    calls: list[dict] = []
    lock = threading.Lock()

    def fake_request(method, url, *, content=None, headers=None, timeout=None):
        with lock:
            calls.append({"method": method, "url": url, "content": content, "headers": dict(headers or {})})
        return httpx.Response(200, request=httpx.Request(method, url), text='{"ok":true}')

    def fake_post(url, *, content=None, headers=None, timeout=None):
        with lock:
            calls.append({"method": "POST", "url": url, "content": content, "headers": dict(headers or {}), "via": "webhook"})
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr("supervisor_api.execution.httpx.request", fake_request)
    monkeypatch.setattr("supervisor_api.webhooks.httpx.post", fake_post)
    return calls


@pytest.fixture()
def auth_on():
    """Enable auth for the duration of the test."""
    from supervisor_api.config import get_settings

    os.environ["REQUIRE_AUTH"] = "true"
    get_settings.cache_clear()
    yield
    os.environ["REQUIRE_AUTH"] = "false"
    get_settings.cache_clear()


def _make_jwt(app_id: str, secret: str, scopes: list[str]) -> str:
    from supervisor_api.auth import sign_jwt

    return sign_jwt(
        {"sub": app_id, "scopes": scopes,
         "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())},
        secret,
    )


def _bootstrap(client, execute_url: str | None) -> tuple[dict, dict]:
    """Create integration, optionally configure execute_url, return (integration, auth_headers)."""
    integ = client.post(
        "/v1/integrations", headers=ADMIN_HEADERS,
        json={"name": f"ap-{execute_url[-8:] if execute_url else 'noexec'}", "scopes": ["*"]},
    ).json()
    if execute_url:
        r = client.put(
            f"/v1/integrations/{integ['id']}/execute-config",
            headers=ADMIN_HEADERS,
            json={"url": execute_url, "method": "POST"},
        )
        assert r.status_code == 200, r.text
    token = _make_jwt(integ["id"], integ["shared_secret"], ["*"])
    return integ, {"Authorization": f"Bearer {token}"}


def test_allow_triggers_downstream_execution(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/refunds")
    r = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r.status_code == 200, r.text
    executes = [c for c in captured if c["url"] == "https://downstream.example/refunds"]
    assert len(executes) == 1, captured
    body = json.loads(executes[0]["content"])
    assert body["action_id"]
    assert body["action_type"] == "refund"
    assert body["decision"]["decision"] == "allow"
    assert executes[0]["headers"]["x-supervisor-action-id"] == body["action_id"]


def test_deny_does_not_execute(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/denied")
    client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 20000, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert not any(c["url"] == "https://downstream.example/denied" for c in captured)


def test_review_approved_executes(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/review-ok")
    dec = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 1200, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"},
    }).json()
    case = next(c for c in client.get("/v1/review-cases?status=pending", headers=headers).json() if c["action_id"] == dec["action_id"])
    client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        headers={**headers, "X-Approver": "ariel@cliocircle.com"},
        json={"decision": "approved", "notes": "ok"},
    )
    executes = [c for c in captured if c["url"] == "https://downstream.example/review-ok"]
    assert len(executes) == 1
    body = json.loads(executes[0]["content"])
    assert body["decision"]["approved_by"] == "ariel@cliocircle.com"


def test_review_rejected_does_not_execute(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/review-no")
    dec = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 1200, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"},
    }).json()
    case = next(c for c in client.get("/v1/review-cases?status=pending", headers=headers).json() if c["action_id"] == dec["action_id"])
    client.post(
        f"/v1/review-cases/{case['id']}/resolve",
        headers={**headers, "X-Approver": "ariel@cliocircle.com"},
        json={"decision": "rejected"},
    )
    assert not any(c["url"] == "https://downstream.example/review-no" for c in captured)


def test_integration_without_execute_url_is_noop(client, captured, auth_on):
    integ, headers = _bootstrap(client, execute_url=None)
    client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    execs = [c for c in captured if c["url"].startswith("https://downstream.example")]
    assert execs == []


def test_execution_hmac_signature_is_verifiable(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/sig")
    client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    call = next(c for c in captured if c["url"] == "https://downstream.example/sig")
    got = call["headers"]["x-supervisor-signature"].removeprefix("sha256=")
    expected = hmac.new(b"test-webhook-secret", call["content"], hashlib.sha256).hexdigest()
    assert hmac.compare_digest(got, expected)


def test_execution_status_endpoint(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/status")
    dec = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    }).json()
    r = client.get(f"/v1/actions/{dec['action_id']}/execution", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["state"] == "success"
    assert data["status_code"] == 200
    assert data["triggered_by"] == "allow"
    assert data["url"] == "https://downstream.example/status"


def test_evidence_chain_includes_action_executed_event(client, captured, auth_on):
    integ, headers = _bootstrap(client, "https://downstream.example/evidence")
    dec = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    }).json()
    bundle = client.get(f"/v1/decisions/{dec['action_id']}/evidence", headers=headers).json()
    assert bundle["chain_ok"] is True
    types = [e["event_type"] for e in bundle["events"]]
    assert "action.executed" in types


def test_execute_config_rejects_non_http_url(client):
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "badurl", "scopes": ["*"]}).json()
    r = client.put(
        f"/v1/integrations/{integ['id']}/execute-config",
        headers=ADMIN_HEADERS,
        json={"url": "ftp://example.com/hook"},
    )
    assert r.status_code == 422


def test_failed_execution_retries_and_records(client, monkeypatch, auth_on):
    import httpx as _httpx

    attempts_urls: list[str] = []

    def failing_request(method, url, *, content=None, headers=None, timeout=None):
        attempts_urls.append(url)
        return _httpx.Response(500, request=_httpx.Request(method, url), text="boom")

    monkeypatch.setattr("supervisor_api.execution.httpx.request", failing_request)
    monkeypatch.setattr("supervisor_api.webhooks.httpx.post",
                        lambda *a, **k: _httpx.Response(200, request=_httpx.Request("POST", "x")))

    integ, headers = _bootstrap(client, "https://downstream.example/fails")
    dec = client.post("/v1/actions/evaluate", headers=headers, json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    }).json()
    assert len(attempts_urls) == 2  # 1 retry

    data = client.get(f"/v1/actions/{dec['action_id']}/execution", headers=headers).json()
    assert data["state"] == "failed"
    assert data["status_code"] == 500
    assert data["attempts"] == 2
