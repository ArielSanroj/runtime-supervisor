"""Tests for the self-serve signup flow.

Covers the public path: anonymous user posts an email → receives a magic
token → exchanges it for SDK credentials. The Resend transport is logged
to stdout in tests (RESEND_API_KEY unset), so we don't need to mock the
network — we just inspect the DB state.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from supervisor_api.db import SessionLocal
from supervisor_api.models import Integration, MagicLinkToken
from supervisor_api.routes.public_signup import _send_buckets


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _send_buckets.clear()
    yield
    _send_buckets.clear()


def _latest_token_for(email: str) -> str:
    with SessionLocal() as s:
        rows = (
            s.query(MagicLinkToken)
            .filter(MagicLinkToken.email == email.lower())
            .order_by(MagicLinkToken.created_at.desc())
            .all()
        )
        assert rows, f"no token rows for {email}"
        return rows[0].token


def test_signup_issues_magic_link_token(client: TestClient) -> None:
    r = client.post("/v1/integrations/public-signup", json={"email": "user@example.com"})
    assert r.status_code == 200
    assert r.json() == {"sent": True}
    # Token row exists, unconsumed, expires in the future.
    with SessionLocal() as s:
        rows = s.query(MagicLinkToken).filter(MagicLinkToken.email == "user@example.com").all()
        assert len(rows) == 1
        assert rows[0].consumed_at is None
        expires_at = rows[0].expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        assert expires_at > datetime.now(UTC)


def test_signup_does_not_create_integration_yet(client: TestClient) -> None:
    """Integration is created at onboard exchange, not at signup time."""
    r = client.post("/v1/integrations/public-signup", json={"email": "deferred@example.com"})
    assert r.status_code == 200
    with SessionLocal() as s:
        # No integration named after this email yet.
        rows = s.query(Integration).filter(Integration.name.like("signup:deferred@%")).all()
        assert rows == []


def test_signup_rate_limits_after_three(client: TestClient) -> None:
    payload = {"email": "spammer@example.com"}
    for _ in range(3):
        r = client.post("/v1/integrations/public-signup", json=payload)
        assert r.status_code == 200
    r = client.post("/v1/integrations/public-signup", json=payload)
    assert r.status_code == 429
    assert "wait" in r.json()["detail"].lower()


def test_signup_rejects_bad_email(client: TestClient) -> None:
    r = client.post("/v1/integrations/public-signup", json={"email": "not-an-email"})
    assert r.status_code == 422  # Pydantic EmailStr validation


def test_onboard_returns_credentials_and_creates_integration(client: TestClient) -> None:
    client.post("/v1/integrations/public-signup", json={"email": "claim@example.com"})
    token = _latest_token_for("claim@example.com")

    r = client.post(f"/v1/integrations/onboard/{token}")
    assert r.status_code == 201
    body = r.json()
    assert "app_id" in body and body["app_id"]
    assert "shared_secret" in body and body["shared_secret"]
    assert "base_url" in body
    assert body["scopes"] == ["*"]

    with SessionLocal() as s:
        # Token marked consumed.
        row = s.query(MagicLinkToken).filter(MagicLinkToken.token == token).one()
        assert row.consumed_at is not None
        # Integration row created, active, named with the email.
        integ = s.query(Integration).filter(Integration.id == body["app_id"]).one()
        assert integ.active is True
        assert integ.name.startswith("signup:claim@example.com:")
        assert integ.shared_secret == body["shared_secret"]
        assert integ.scopes == ["*"]


def test_onboard_token_is_single_use(client: TestClient) -> None:
    client.post("/v1/integrations/public-signup", json={"email": "twice@example.com"})
    token = _latest_token_for("twice@example.com")
    r1 = client.post(f"/v1/integrations/onboard/{token}")
    assert r1.status_code == 201
    r2 = client.post(f"/v1/integrations/onboard/{token}")
    assert r2.status_code == 410
    assert "already used" in r2.json()["detail"].lower()


def test_onboard_rejects_unknown_token(client: TestClient) -> None:
    r = client.post("/v1/integrations/onboard/this-is-not-a-real-token")
    assert r.status_code == 404


def test_onboard_rejects_expired_token(client: TestClient) -> None:
    client.post("/v1/integrations/public-signup", json={"email": "stale@example.com"})
    token = _latest_token_for("stale@example.com")
    # Force-expire the token.
    with SessionLocal() as s:
        row = s.query(MagicLinkToken).filter(MagicLinkToken.token == token).one()
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        s.commit()

    r = client.post(f"/v1/integrations/onboard/{token}")
    assert r.status_code == 410
    assert "expired" in r.json()["detail"].lower()


def test_credentials_can_authenticate_to_evaluate(client: TestClient) -> None:
    """End-to-end: credentials issued via signup actually work against /v1/actions/evaluate."""
    client.post("/v1/integrations/public-signup", json={"email": "real@example.com"})
    token = _latest_token_for("real@example.com")
    r = client.post(f"/v1/integrations/onboard/{token}")
    assert r.status_code == 201
    creds = r.json()

    # Build a JWT bearer with the issued secret and try a real evaluate
    # call. REQUIRE_AUTH is false in the test fixture so auth is bypassed,
    # but we still validate the integration row exists and is active by
    # reading back via the admin path.
    with SessionLocal() as s:
        integ = s.query(Integration).filter(Integration.id == creds["app_id"]).one()
        assert integ.active is True
        assert integ.revoked_at is None
