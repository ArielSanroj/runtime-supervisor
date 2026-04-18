"""Outbound webhook dispatch with async retry queue.

First attempt runs in-process via FastAPI BackgroundTasks. On failure,
the delivery is persisted with state=pending and a next_retry_at set
per the exponential backoff schedule. A separate retry worker
(supervisor_api.retry_worker) picks up due deliveries and re-attempts
until success or state=dead after MAX_ATTEMPTS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal
from .models import WebhookDelivery, WebhookSubscription
from .telemetry import get_tracer

_tracer = get_tracer(__name__)

EventType = str

_TIMEOUT_SECONDS = 3.0
MAX_ATTEMPTS = 5
# Backoff per attempt number (attempt 1 = first retry after the initial try failed).
# Seconds: 1, 5, 30, 120, 600. After attempt 5 fails the delivery goes dead.
_BACKOFF_SECONDS = [1, 5, 30, 120, 600]


def sign(body: bytes) -> str:
    secret = get_settings().webhook_secret.encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _next_retry_at(attempts: int) -> datetime | None:
    """Return when to try again after `attempts` total attempts. None if dead."""
    if attempts >= MAX_ATTEMPTS:
        return None
    idx = min(attempts, len(_BACKOFF_SECONDS) - 1)
    return datetime.now(UTC) + timedelta(seconds=_BACKOFF_SECONDS[idx])


def _attempt_post(url: str, body: bytes, event_type: str, signature: str) -> tuple[int | None, str | None]:
    try:
        r = httpx.post(
            url,
            content=body,
            headers={
                "content-type": "application/json",
                "x-supervisor-event": event_type,
                "x-supervisor-signature": f"sha256={signature}",
            },
            timeout=_TIMEOUT_SECONDS,
        )
        if 200 <= r.status_code < 300:
            return r.status_code, None
        return r.status_code, f"HTTP {r.status_code}: {r.text[:200]}"
    except httpx.HTTPError as e:
        return None, str(e)[:500]


def _deliver_one(sub: WebhookSubscription, event_type: str, payload: dict[str, Any]) -> None:
    body = json.dumps({"event": event_type, "data": payload}, default=str).encode()
    signature = sign(body)
    status_code, error = _attempt_post(sub.url, body, event_type, signature)
    attempts = 1

    db = SessionLocal()
    try:
        state = "success" if error is None else ("pending" if attempts < MAX_ATTEMPTS else "dead")
        db.add(
            WebhookDelivery(
                subscription_id=sub.id,
                event_type=event_type,
                payload=payload,
                status_code=status_code,
                error=error,
                attempts=attempts,
                state=state,
                delivered_at=datetime.now(UTC) if error is None else None,
                next_retry_at=None if error is None or state == "dead" else _next_retry_at(attempts),
            )
        )
        db.commit()
    finally:
        db.close()


def _dispatch_impl(event_type: str, payload: dict[str, Any]) -> None:
    """Fetch active subs for this event and deliver once to each."""
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


def retry_due_deliveries(batch_size: int = 50) -> dict[str, int]:
    """Find pending deliveries whose next_retry_at has passed, re-attempt each.

    Returns counts by outcome — safe to call from a worker loop or a cron.
    """
    db = SessionLocal()
    now = datetime.now(UTC)
    counts = {"retried": 0, "succeeded": 0, "pending": 0, "dead": 0}
    try:
        rows = db.execute(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.state == "pending",
                WebhookDelivery.next_retry_at.is_not(None),
                WebhookDelivery.next_retry_at <= now,
            )
            .order_by(WebhookDelivery.next_retry_at.asc())
            .limit(batch_size)
        ).scalars().all()

        for row in rows:
            sub = db.get(WebhookSubscription, row.subscription_id)
            if sub is None or not sub.active:
                row.state = "dead"
                row.next_retry_at = None
                row.error = (row.error or "") + " | subscription gone"
                counts["dead"] += 1
                continue

            body = json.dumps({"event": row.event_type, "data": row.payload}, default=str).encode()
            signature = sign(body)
            status_code, error = _attempt_post(sub.url, body, row.event_type, signature)
            row.attempts += 1
            row.status_code = status_code
            counts["retried"] += 1
            if error is None:
                row.state = "success"
                row.error = None
                row.delivered_at = datetime.now(UTC)
                row.next_retry_at = None
                counts["succeeded"] += 1
            elif row.attempts >= MAX_ATTEMPTS:
                row.state = "dead"
                row.error = error
                row.next_retry_at = None
                counts["dead"] += 1
            else:
                row.error = error
                row.next_retry_at = _next_retry_at(row.attempts)
                counts["pending"] += 1
        db.commit()
    finally:
        db.close()
    return counts
