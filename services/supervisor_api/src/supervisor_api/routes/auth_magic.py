"""Passwordless magic-link auth.

Two endpoints:
  POST /v1/auth/magic-link/send         — public; rate-limited per email.
  GET  /v1/auth/magic-link/{token}      — public; single-use exchange.
                                          Returns the session JWT in JSON
                                          so the Next.js page can set the
                                          cookie and redirect.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..email import send_magic_link
from ..models import MagicLinkToken, User
from .billing import _issue_magic_link  # reuse the same insert + URL builder
from .users import build_session_jwt, UserOut

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth", tags=["auth"])


# Per-email send rate limit: 3 sends / hour. Prevents email-bombing an
# address. In-process; for multi-replica move to Redis.
_SEND_WINDOW_SECONDS = 3600.0
_SEND_LIMIT = 3
_send_buckets: dict[str, deque[float]] = defaultdict(deque)
_send_lock = Lock()


def _check_send_rate(email: str) -> None:
    now = time.monotonic()
    with _send_lock:
        bucket = _send_buckets[email]
        while bucket and now - bucket[0] > _SEND_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= _SEND_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="too many magic link requests — wait an hour",
            )
        bucket.append(now)


class SendRequest(BaseModel):
    email: EmailStr


class SendResponse(BaseModel):
    sent: bool


class ExchangeResponse(BaseModel):
    token: str
    user: UserOut


@router.post("/magic-link/send", response_model=SendResponse)
def send(body: SendRequest, db: Session = Depends(get_db)) -> SendResponse:
    email = body.email.lower()
    _check_send_rate(email)
    # Always 200 even when the user doesn't exist — don't leak which emails
    # are registered. Send only when there IS a builder user; for unknown
    # emails just no-op silently.
    u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if u is None or not u.active or u.tier != "builder":
        log.info("magic-link/send: email %s has no eligible builder account", email)
        return SendResponse(sent=True)
    link_url = _issue_magic_link(db, email)
    try:
        send_magic_link(email, link_url)
    except Exception:
        log.exception("magic-link/send: email send failed for %s", email)
        # Still return ok; the email failure is logged for ops to investigate.
    return SendResponse(sent=True)


@router.get("/magic-link/{token}", response_model=ExchangeResponse)
def exchange(token: str, db: Session = Depends(get_db)) -> ExchangeResponse:
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

    u = db.execute(select(User).where(User.email == row.email)).scalar_one_or_none()
    if u is None or not u.active:
        raise HTTPException(status_code=404, detail="user not found")

    row.consumed_at = datetime.now(UTC)
    db.commit()

    jwt = build_session_jwt(u)
    return ExchangeResponse(
        token=jwt,
        user=UserOut(
            id=u.id,
            email=u.email,
            role=u.role,
            tenant_id=u.tenant_id,
            active=u.active,
            created_at=u.created_at,
        ),
    )
