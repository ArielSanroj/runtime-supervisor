"""Public self-serve signup for SDK credentials.

Two endpoints:
  POST /v1/integrations/public-signup    — public; rate-limited per email.
  POST /v1/integrations/onboard/{token}  — public; single-use token exchange.

Flow:
  1. User submits email on /scan or landing.
  2. Backend issues a magic-link token bound to that email and emails the
     user a link to {SITE_URL}/onboard/{token}.
  3. User opens the link; the frontend page POSTs to /onboard/{token}.
  4. Backend creates an active Integration on demand, marks the token
     consumed, and returns {app_id, shared_secret, base_url, scopes} once.

Integration creation is deferred until token exchange — this avoids the
"linking the pre-created integration to the token" problem and means
abandoned signups never leak inactive rows.
"""
from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from .. import audit, auth
from ..config import get_settings
from ..db import get_db
from ..email import send_signup_link
from ..models import Integration, MagicLinkToken

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/integrations", tags=["public-signup"])


# Per-email rate limit: 3 signups / hour. Same posture as auth_magic.
# In-process; for multi-replica move to Redis.
_SEND_WINDOW_SECONDS = 3600.0
_SEND_LIMIT = 3
_send_buckets: dict[str, deque[float]] = defaultdict(deque)
_send_lock = Lock()

# Signup tokens live longer than login links — credentials are a one-shot
# moment users may want to revisit from another device.
_SIGNUP_TTL_MINUTES = 30


def _check_send_rate(email: str) -> None:
    now = time.monotonic()
    with _send_lock:
        bucket = _send_buckets[email]
        while bucket and now - bucket[0] > _SEND_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= _SEND_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="too many signup requests — wait an hour",
            )
        bucket.append(now)


def _issue_signup_token(db: Session, email: str) -> str:
    """Insert a fresh single-use signup token, return the URL the user clicks."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(minutes=_SIGNUP_TTL_MINUTES)
    db.add(MagicLinkToken(token=token, email=email.lower(), expires_at=expires_at))
    db.commit()
    site = get_settings().site_url.rstrip("/")
    return f"{site}/onboard/{token}"


class SignupRequest(BaseModel):
    email: EmailStr


class SignupResponse(BaseModel):
    sent: bool


class OnboardResponse(BaseModel):
    app_id: str = Field(description="Use as SUPERVISOR_APP_ID env var.")
    shared_secret: str = Field(description="Use as SUPERVISOR_SECRET env var. Shown once — copy now.")
    base_url: str = Field(description="Use as SUPERVISOR_BASE_URL env var.")
    scopes: list[str]


@router.post("/public-signup", response_model=SignupResponse)
def public_signup(body: SignupRequest, db: Session = Depends(get_db)) -> SignupResponse:
    """Issue a signup token and email it to the user.

    Always returns 200 — we don't leak whether the email is rate-limited
    individually beyond the 429 block.
    """
    email = body.email.lower()
    _check_send_rate(email)
    link_url = _issue_signup_token(db, email)
    try:
        send_signup_link(email, link_url)
    except Exception:
        log.exception("public-signup: email send failed for %s", email)
        # Still return ok; failure is logged for ops to investigate. The
        # token is valid for 30 min so user can request another if needed.
    return SignupResponse(sent=True)


@router.post("/onboard/{token}", response_model=OnboardResponse, status_code=201)
def onboard(token: str, db: Session = Depends(get_db)) -> OnboardResponse:
    """Exchange a signup token for SDK credentials.

    Single-use. Creates the Integration row on demand and returns the
    shared_secret only this once. Re-hitting with the same token returns
    410.
    """
    row = db.get(MagicLinkToken, token)
    if row is None:
        raise HTTPException(status_code=404, detail="link not found")
    if row.consumed_at is not None:
        raise HTTPException(status_code=410, detail="link already used")
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < datetime.now(UTC):
        raise HTTPException(status_code=410, detail="link expired")

    secret = auth.generate_secret()

    # Resolve default tenant — same posture as admin POST /v1/integrations.
    from ..auth import _default_tenant_id

    tenant_id = _default_tenant_id(db)

    # Name encodes the email + a timestamp so it's both human-readable in
    # the admin list and uniquely-named (avoids unique(name) collisions
    # if the same email signs up twice).
    name = f"signup:{row.email}:{int(time.time())}"

    integration = Integration(
        name=name,
        shared_secret=secret,
        scopes=["*"],
        active=True,
        tenant_id=tenant_id,
    )
    db.add(integration)

    row.consumed_at = datetime.now(UTC)

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        log.exception("onboard: failed to create integration for %s", row.email)
        raise HTTPException(status_code=500, detail=f"signup failed: {e}") from e

    db.refresh(integration)

    audit.record(
        actor="public-signup",
        action="integration.create",
        target_type="integration",
        target_id=integration.id,
        details={"name": integration.name, "email": row.email, "via": "public-signup"},
    )

    settings = get_settings()
    return OnboardResponse(
        app_id=integration.id,
        shared_secret=secret,
        base_url=settings.public_api_url,
        scopes=list(integration.scopes or []),
    )
