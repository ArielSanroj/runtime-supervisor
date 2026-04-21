"""Callback-based HITL.

The SDK spins up a daemon thread that polls the supervisor for pending
reviews and invokes the user's callback with each new case. The callback
can:

1. Return "approved" / "rejected" → the daemon resolves the case.
2. Return None → the daemon leaves the case pending; the user resolves it
   later via their own channel (Slack click, email link, etc.) by calling
   `agentic_controls.resolve(review_id, "approved", approver="name")`.

Design notes:
- Polling interval is 5s by default; low enough for demo use cases,
  not so tight that we hammer the backend.
- The daemon dedups: a given review case is passed to the callback at
  most once per process lifetime.
- If the callback raises, we log + continue — one bad callback won't kill
  subsequent reviews.
- Thread exits cleanly on atexit.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal

log = logging.getLogger(__name__)

ReviewDecision = Literal["approved", "rejected"]


@dataclass(frozen=True)
class ReviewCase:
    """What the callback receives. Mirrors supervisor_client.ReviewCase with
    extra convenience fields."""

    id: str
    action_id: str
    action_type: str
    action_payload: dict[str, Any]
    risk_score: int
    policy_hits: list[dict[str, Any]]
    created_at: str


OnReviewCallback = Callable[[ReviewCase], ReviewDecision | None]

# Module-level state — single daemon per process.
_callback: OnReviewCallback | None = None
_daemon: threading.Thread | None = None
_stop_event = threading.Event()
_seen_ids: set[str] = set()
_lock = threading.Lock()
_poll_interval_s = 5.0


def set_on_review(
    callback: OnReviewCallback | None,
    *,
    poll_interval_seconds: float = 5.0,
) -> None:
    """Register a callback that fires for each pending review case.

    Pass `None` to unregister + stop the daemon. Safe to call repeatedly.
    The callback runs in a background thread — don't do blocking IO on the
    main thread's event loop from it.
    """
    global _callback, _daemon, _poll_interval_s

    with _lock:
        _callback = callback
        _poll_interval_s = poll_interval_seconds

        if callback is None:
            _stop_daemon_unlocked()
            return

        if _daemon is None or not _daemon.is_alive():
            _stop_event.clear()
            _daemon = threading.Thread(target=_poll_loop, daemon=True, name="agentic-review-poll")
            _daemon.start()
            atexit.register(_stop_daemon)


def _stop_daemon_unlocked() -> None:
    global _daemon
    _stop_event.set()
    if _daemon and _daemon.is_alive():
        _daemon.join(timeout=2.0)
    _daemon = None


def _stop_daemon() -> None:
    with _lock:
        _stop_daemon_unlocked()


def resolve(review_id: str, decision: ReviewDecision, approver: str, notes: str | None = None) -> None:
    """Resolve a pending review. Use when your callback returned None and
    the human later decided via another channel."""
    from supervisor_guards.config import get_client

    client = get_client()
    client.resolve_review(review_id, {"decision": decision, "notes": notes}, approver=approver)


def _poll_loop() -> None:
    while not _stop_event.is_set():
        try:
            _tick()
        except Exception as exc:  # noqa: BLE001
            log.warning("review daemon tick failed: %s", exc)
        _stop_event.wait(_poll_interval_s)


def _tick() -> None:
    from supervisor_guards.config import get_client

    if _callback is None:
        return
    client = get_client()
    pending = client.list_reviews("pending")
    for raw in pending:
        case_id = raw.id
        if case_id in _seen_ids:
            continue
        _seen_ids.add(case_id)
        case = _to_case(raw, client)
        try:
            result = _callback(case)
        except Exception as exc:  # noqa: BLE001
            log.exception("on_review callback raised for %s: %s", case_id, exc)
            continue
        if result in ("approved", "rejected"):
            try:
                client.resolve_review(
                    case_id,
                    {"decision": result},
                    approver="agentic-controls-callback",
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("resolve_review failed for %s: %s", case_id, exc)


def _to_case(raw: Any, client: Any) -> ReviewCase:
    """Normalize the SDK's ReviewCase (has only summary fields) into our
    richer ReviewCase. Fetches the full item to get payload + policy_hits."""
    full = client.get_review(raw.id) if hasattr(client, "get_review") else None
    if full:
        return ReviewCase(
            id=full.get("id", raw.id),
            action_id=full.get("action_id", raw.action_id),
            action_type=full.get("action_type", raw.action_type),
            action_payload=full.get("action_payload", {}),
            risk_score=full.get("risk_score", raw.risk_score),
            policy_hits=full.get("policy_hits", []),
            created_at=full.get("created_at", raw.created_at),
        )
    return ReviewCase(
        id=raw.id,
        action_id=raw.action_id,
        action_type=raw.action_type,
        action_payload={},
        risk_score=raw.risk_score,
        policy_hits=[],
        created_at=raw.created_at,
    )
