"""action_proxy — execute approved actions against the integration's downstream URL.

Called from FastAPI BackgroundTasks when:
  - /v1/actions/evaluate produces a direct `allow` decision, or
  - a review resolves with `approved`.

Signs the payload with WEBHOOK_SECRET (same HMAC scheme as outbound webhooks)
and sends `x-supervisor-action-id` so the downstream can dedupe. On failure,
one retry; all outcomes recorded in action_executions + hash-chain evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import httpx

from . import evidence
from .config import get_settings
from .db import SessionLocal
from .models import Action, ActionExecution, Decision, Integration, ReviewItem
from .telemetry import get_tracer

_tracer = get_tracer(__name__)

_TIMEOUT_SECONDS = 5.0
_MAX_ATTEMPTS = 2


def _sign(body: bytes) -> str:
    secret = get_settings().webhook_secret.encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _build_body(action: Action, decision: Decision | None, review: ReviewItem | None) -> bytes:
    return json.dumps(
        {
            "action_id": action.id,
            "action_type": action.action_type,
            "payload": action.payload,
            "decision": {
                "decision": decision.decision if decision else "approved",
                "reasons": [h.get("reason") for h in (decision.policy_hits if decision else []) or []],
                "risk_score": decision.risk_score if decision else 0,
                "policy_version": decision.policy_version if decision else "review",
                "approved_by": review.approver if review else None,
                "approved_at": review.resolved_at.isoformat() if review and review.resolved_at else None,
            },
        },
        default=str,
    ).encode()


def execute(action_id: str, *, triggered_by: str, integration_id: str | None = None) -> None:
    """Runs in BackgroundTasks after the request completes."""
    span = _tracer.start_span("execution.execute")
    span.set_attribute("supervisor.action_id", action_id)
    span.set_attribute("supervisor.triggered_by", triggered_by)
    if integration_id:
        span.set_attribute("supervisor.integration_id", integration_id)
    db = SessionLocal()
    try:
        action = db.get(Action, action_id)
        if action is None:
            return

        integration = db.get(Integration, integration_id) if integration_id else None
        if integration is None or not integration.execute_url:
            return

        # Idempotency: one execution per action, ever.
        existing = db.query(ActionExecution).filter_by(action_id=action_id).one_or_none()
        if existing is not None:
            return

        body = _build_body(action, action.decision, action.review)
        signature = _sign(body)

        row = ActionExecution(
            action_id=action.id,
            integration_id=integration.id,
            url=integration.execute_url,
            method=integration.execute_method or "POST",
            state="pending",
            triggered_by=triggered_by,
        )
        db.add(row)
        db.flush()

        status_code: int | None = None
        response_body: str | None = None
        error: str | None = None
        attempts = 0

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            attempts = attempt
            try:
                r = httpx.request(
                    row.method,
                    row.url,
                    content=body,
                    headers={
                        "content-type": "application/json",
                        "x-supervisor-action-id": action.id,
                        "x-supervisor-event": "action.execute",
                        "x-supervisor-signature": f"sha256={signature}",
                    },
                    timeout=_TIMEOUT_SECONDS,
                )
                status_code = r.status_code
                response_body = r.text[:4000]
                if 200 <= r.status_code < 300:
                    error = None
                    break
                error = f"HTTP {r.status_code}"
            except httpx.HTTPError as e:
                error = str(e)[:500]

        row.status_code = status_code
        row.response_body = response_body
        row.error = error
        row.attempts = attempts
        row.state = "success" if error is None else "failed"
        row.executed_at = datetime.now(UTC)

        evidence.append(db, action_id=action.id, event_type="action.executed", payload={
            "url": row.url, "method": row.method,
            "status_code": status_code, "state": row.state,
            "attempts": attempts, "triggered_by": triggered_by,
        })
        db.commit()
        span.set_attribute("supervisor.execution_state", row.state)
        if status_code is not None:
            span.set_attribute("http.status_code", status_code)
    finally:
        db.close()
        span.end()


def retry_dead_or_failed(action_id: str) -> dict[str, Any]:
    """Admin-triggered retry for dead/failed executions.

    Resets idempotency by deleting the existing ActionExecution row, then
    calls execute() again which will create a fresh row.
    """
    db = SessionLocal()
    try:
        row = db.query(ActionExecution).filter_by(action_id=action_id).one_or_none()
        if row is None:
            raise LookupError(f"no execution recorded for action {action_id}")
        if row.state == "success":
            return {"skipped": True, "reason": "already successful"}
        integration_id = row.integration_id
        db.delete(row)
        db.commit()
    finally:
        db.close()

    execute(action_id, triggered_by="retry", integration_id=integration_id)

    db = SessionLocal()
    try:
        row = db.query(ActionExecution).filter_by(action_id=action_id).one_or_none()
        return build_execution_out(row) if row else {"skipped": True, "reason": "no row after retry"}
    finally:
        db.close()


def build_execution_out(row: ActionExecution) -> dict[str, Any]:
    return {
        "id": row.id,
        "action_id": row.action_id,
        "integration_id": row.integration_id,
        "url": row.url,
        "method": row.method,
        "status_code": row.status_code,
        "error": row.error,
        "attempts": row.attempts,
        "state": row.state,
        "triggered_by": row.triggered_by,
        "queued_at": row.queued_at,
        "executed_at": row.executed_at,
    }
