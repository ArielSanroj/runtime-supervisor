"""JWT (HS256) + admin bootstrap auth for the integration API.

We do our own tiny HS256 signer to avoid a runtime dep on PyJWT —
claims are a narrow, controlled set.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Integration


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign_jwt(claims: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(claims, separators=(",", ":"), default=str).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    return json.loads(_b64url_decode(parts[1]))


def verify_jwt(token: str, secret: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWT")
    h, p, sig = parts
    expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_decode(sig), expected):
        raise ValueError("bad signature")
    claims = json.loads(_b64url_decode(p))
    exp = claims.get("exp")
    if exp is not None and int(exp) < int(datetime.now(UTC).timestamp()):
        raise ValueError("token expired")
    return claims


def generate_secret() -> str:
    """Opaque URL-safe 32-byte secret — surfaced once to the integration owner."""
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class Principal:
    integration_id: str
    name: str
    scopes: list[str]
    # Phase 1 multi-tenant: every verified request carries the tenant the
    # integration was registered against. Phase 2 filters queries by this.
    # Nullable for legacy integrations that haven't been assigned a tenant
    # yet — those fall through to the "default" tenant in the backfilled DB.
    tenant_id: str | None = None


def _match_scope(granted: list[str], required: str) -> bool:
    if "*" in granted:
        return True
    return required in granted


def _extract_bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return authorization.split(None, 1)[1].strip()


def _lookup_integration(db: Session, token: str) -> Integration:
    try:
        claims = decode_jwt_unverified(token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}") from e

    sub = claims.get("sub") or claims.get("iss")
    if not sub:
        raise HTTPException(status_code=401, detail="token missing sub claim")

    integration = db.get(Integration, sub)
    if integration is None or integration.revoked_at is not None or not integration.active:
        raise HTTPException(status_code=401, detail="integration not found or revoked")

    try:
        claims = verify_jwt(token, integration.shared_secret)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"invalid token: {e}") from e
    return integration


def require_scope(required: str):
    """Dependency factory: enforce JWT auth + scope match for a given action_type.

    If REQUIRE_AUTH=false (dev/test default), dependency is a no-op returning
    a synthetic 'dev' principal.
    """

    def _dep(
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> Principal:
        if not get_settings().require_auth:
            return Principal(integration_id="dev", name="dev", scopes=["*"], tenant_id=None)

        token = _extract_bearer(authorization)
        integration = _lookup_integration(db, token)
        if not _match_scope(integration.scopes or [], required):
            raise HTTPException(status_code=403, detail=f"scope '{required}' not granted")
        return Principal(
            integration_id=integration.id,
            name=integration.name,
            scopes=integration.scopes or [],
            tenant_id=integration.tenant_id,
        )

    return _dep


def require_any_scope(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    """For endpoints not tied to a single action_type (e.g. listing reviews)."""
    if not get_settings().require_auth:
        return Principal(integration_id="dev", name="dev", scopes=["*"], tenant_id=None)
    token = _extract_bearer(authorization)
    integration = _lookup_integration(db, token)
    return Principal(
        integration_id=integration.id,
        name=integration.name,
        scopes=integration.scopes or [],
        tenant_id=integration.tenant_id,
    )


def require_admin(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    expected = get_settings().admin_bootstrap_token
    if not expected:
        raise HTTPException(status_code=503, detail="admin token not configured")
    if not x_admin_token or not hmac.compare_digest(x_admin_token, expected):
        raise HTTPException(status_code=401, detail="invalid admin token")


def require_tenant_id(principal: Principal = Depends(require_any_scope)) -> str:
    """Dependency that returns the tenant_id bound to the caller's JWT.

    Phase 2 uses this on every tenant-scoped route so queries can apply
    `WHERE tenant_id = :tenant_id` without reaching into the Principal
    themselves. Routes declare `tenant_id: str = Depends(require_tenant_id)`
    and filter directly with that string.

    Failure modes:
      - No bearer → 401 (from require_any_scope).
      - Verified integration but `tenant_id` column is NULL → 403. This
        should not happen after Phase 1's backfill, but the explicit
        rejection prevents silent cross-tenant leakage via unscoped rows.
      - REQUIRE_AUTH=false (dev) → returns "default-dev-tenant" sentinel
        so local tests don't need a real tenant row.
    """
    if principal.tenant_id is None:
        if principal.integration_id == "dev":
            return "default-dev-tenant"
        raise HTTPException(
            status_code=403,
            detail="integration is not assigned to a tenant — assign via /v1/integrations/{id}",
        )
    return principal.tenant_id
