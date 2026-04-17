"""Integration API flow: register app → get JWT → call evaluate with it."""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


def _make_jwt(app_id: str, secret: str, scopes: list[str], expires_in: int = 3600) -> str:
    from supervisor_api.auth import sign_jwt

    claims = {
        "sub": app_id,
        "scopes": scopes,
        "exp": int((datetime.now(UTC) + timedelta(seconds=expires_in)).timestamp()),
    }
    return sign_jwt(claims, secret)


def test_requires_admin_token_to_create_integration(client):
    r = client.post("/v1/integrations", json={"name": "acme"})
    assert r.status_code == 401


def test_admin_can_create_and_list_integration(client):
    r = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "acme", "scopes": ["refund"]})
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["name"] == "acme"
    assert created["scopes"] == ["refund"]
    assert created["shared_secret"]  # surfaced once

    lst = client.get("/v1/integrations", headers=ADMIN_HEADERS).json()
    assert any(i["id"] == created["id"] for i in lst)


def test_create_rejects_duplicate_name(client):
    client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "dup"})
    r = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "dup"})
    assert r.status_code == 409


def test_rotate_secret_changes_it(client):
    r = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "rot"}).json()
    s1 = r["shared_secret"]
    r2 = client.post(f"/v1/integrations/{r['id']}/rotate-secret", headers=ADMIN_HEADERS).json()
    assert r2["shared_secret"] != s1


def test_revoke_disables_integration(client):
    r = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "rev"}).json()
    r2 = client.post(f"/v1/integrations/{r['id']}/revoke", headers=ADMIN_HEADERS).json()
    assert r2["active"] is False
    assert r2["revoked_at"] is not None


@pytest.fixture()
def auth_client(client):
    """Same client but with REQUIRE_AUTH=true for the duration of the test."""
    from supervisor_api.config import get_settings

    os.environ["REQUIRE_AUTH"] = "true"
    get_settings.cache_clear()
    yield client
    os.environ["REQUIRE_AUTH"] = "false"
    get_settings.cache_clear()


def test_evaluate_rejects_missing_token_when_auth_required(auth_client):
    r = auth_client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": {"amount": 50}})
    assert r.status_code == 401


def test_evaluate_accepts_valid_jwt(client, auth_client):
    created = client.post(
        "/v1/integrations", headers=ADMIN_HEADERS, json={"name": "evaluator", "scopes": ["refund"]}
    ).json()
    token = _make_jwt(created["id"], created["shared_secret"], ["refund"])
    r = auth_client.post(
        "/v1/actions/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action_type": "refund", "payload": {"amount": 50, "customer_id": "c1", "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "allow"


def test_evaluate_rejects_wrong_scope(client, auth_client):
    created = client.post(
        "/v1/integrations", headers=ADMIN_HEADERS, json={"name": "narrow", "scopes": ["payment"]}
    ).json()
    token = _make_jwt(created["id"], created["shared_secret"], ["payment"])
    r = auth_client.post(
        "/v1/actions/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action_type": "refund", "payload": {}},
    )
    assert r.status_code == 403


def test_evaluate_rejects_bad_signature(client, auth_client):
    created = client.post(
        "/v1/integrations", headers=ADMIN_HEADERS, json={"name": "bad", "scopes": ["*"]}
    ).json()
    token = _make_jwt(created["id"], "wrong-secret", ["*"])
    r = auth_client.post(
        "/v1/actions/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action_type": "refund", "payload": {}},
    )
    assert r.status_code == 401


def test_evaluate_rejects_revoked_integration(client, auth_client):
    created = client.post(
        "/v1/integrations", headers=ADMIN_HEADERS, json={"name": "revoked", "scopes": ["*"]}
    ).json()
    client.post(f"/v1/integrations/{created['id']}/revoke", headers=ADMIN_HEADERS)
    token = _make_jwt(created["id"], created["shared_secret"], ["*"])
    r = auth_client.post(
        "/v1/actions/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={"action_type": "refund", "payload": {}},
    )
    assert r.status_code == 401
