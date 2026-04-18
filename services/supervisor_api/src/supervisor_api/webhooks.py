"""Outbound webhook dispatch.

Runs in a FastAPI BackgroundTasks after the request completes so callers
don't wait on the subscriber's response. Each attempt records a row in
`webhook_deliveries` with status_code or error. One automatic retry on
network error; no exponential backoff (Phase 3 concern).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal
from .models import WebhookDelivery, WebhookSubscription
from .telemetry import get_tracer

_tracer = get_tracer(__name__)

EventType = str  # "decision.made" | "review.resolved" | "action.denied"

_TIMEOUT_SECONDS = 3.0
_MAX_ATTEMPTS = 2


def sign(body: bytes) -> str:
    secret = get_settings().webhook_secret.encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _deliver_one(sub: WebhookSubscription, event_type: str, payload: dict[str, Any]) -> None:
    body = json.dumps({"event": event_type, "data": payload}, default=str).encode()
    signature = sign(body)
    status_code: int | None = None
    error: str | None = None
    attempts = 0

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        attempts = attempt
        try:
            r = httpx.post(
                sub.url,
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-supervisor-event": event_type,
                    "x-supervisor-signature": f"sha256={signature}",
                },
                timeout=_TIMEOUT_SECONDS,
            )
            status_code = r.status_code
            if 200 <= r.status_code < 300:
                error = None
                break
            error = f"HTTP {r.status_code}: {r.text[:200]}"
        except httpx.HTTPError as e:
            error = str(e)[:500]

    db = SessionLocal()
    try:
        db.add(
            WebhookDelivery(
                subscription_id=sub.id,
                event_type=event_type,
                payload=payload,
                status_code=status_code,
                error=error,
                attempts=attempts,
                delivered_at=datetime.now(UTC) if error is None else None,
            )
        )
        db.commit()
    finally:
        db.close()


def _dispatch_impl(event_type: str, payload: dict[str, Any]) -> None:
    """Fetch active subs for this event and deliver to each. Blocks on HTTP.

    Intended to be invoked via FastAPI BackgroundTasks so it runs after the
    response is sent. Opens its own DB session because the request session
    is already closed by the time this runs.
    """
    db: Session = SessionLocal()
    try:
        subs = db.execute(
            select(WebhookSubscription).where(WebhookSubscription.active.is_(True))
        ).scalars().all()
        targets = [s for s in subs if event_type in (s.events or [])]
    finally:
        db.close()

    for sub in targets:
        _deliver_one(sub, event_type, payload)


def dispatch(event_type: str, payload: dict[str, Any]) -> None:
    with _tracer.start_as_current_span("webhooks.dispatch") as span:
        span.set_attribute("webhook.event_type", event_type)
        _dispatch_impl(event_type, payload)
