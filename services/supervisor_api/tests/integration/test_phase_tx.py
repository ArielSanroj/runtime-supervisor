"""Phase T+X scaffold: tenants CRUD + user accounts + login."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


def test_tenant_crud(client):
    r = client.post("/v1/tenants", headers=ADMIN_HEADERS, json={"name": "acme"})
    assert r.status_code == 201
    t = r.json()
    assert t["name"] == "acme" and t["active"] is True

    lst = client.get("/v1/tenants", headers=ADMIN_HEADERS).json()
    assert any(row["id"] == t["id"] for row in lst)

    got = client.get(f"/v1/tenants/{t['id']}", headers=ADMIN_HEADERS).json()
    assert got["name"] == "acme"


def test_tenant_duplicate_name_is_conflict(client):
    client.post("/v1/tenants", headers=ADMIN_HEADERS, json={"name": "dup"})
    r = client.post("/v1/tenants", headers=ADMIN_HEADERS, json={"name": "dup"})
    assert r.status_code == 409


def test_user_crud_and_login(client):
    # Admin creates a user
    r = client.post("/v1/users", headers=ADMIN_HEADERS, json={
        "email": "ops@acme.com", "password": "strongpassword", "role": "ops",
    })
    assert r.status_code == 201
    u = r.json()
    assert u["email"] == "ops@acme.com"
    assert u["role"] == "ops"

    # Login succeeds with correct password
    lr = client.post("/v1/auth/login", json={"email": "ops@acme.com", "password": "strongpassword"})
    assert lr.status_code == 200
    body = lr.json()
    assert body["user"]["id"] == u["id"]
    assert body["user"]["role"] == "ops"
    assert body["token"].count(".") == 2  # JWT shape

    # Wrong password → 401
    bad = client.post("/v1/auth/login", json={"email": "ops@acme.com", "password": "wrong"})
    assert bad.status_code == 401


def test_user_create_requires_admin(client):
    r = client.post("/v1/users", json={"email": "x@y.com", "password": "p" * 12, "role": "ops"})
    assert r.status_code == 401


def test_user_create_rejects_invalid_role(client):
    r = client.post("/v1/users", headers=ADMIN_HEADERS, json={
        "email": "bad@y.com", "password": "p" * 12, "role": "superuser",
    })
    assert r.status_code == 400


def test_login_unknown_user_is_401(client):
    r = client.post("/v1/auth/login", json={"email": "nobody@nope.com", "password": "x" * 12})
    assert r.status_code == 401


def test_login_token_is_signed_and_verifiable(client):
    client.post("/v1/users", headers=ADMIN_HEADERS, json={
        "email": "verify@y.com", "password": "strongpassword", "role": "auditor",
    })
    tok = client.post("/v1/auth/login", json={"email": "verify@y.com", "password": "strongpassword"}).json()["token"]

    from supervisor_api.auth import verify_jwt
    from supervisor_api.config import get_settings

    claims = verify_jwt(tok, get_settings().webhook_secret)
    assert claims["email"] == "verify@y.com"
    assert claims["role"] == "auditor"
    assert claims["kind"] == "session"
