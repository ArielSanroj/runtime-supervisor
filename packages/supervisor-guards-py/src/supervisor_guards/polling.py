"""Polling helpers for the review resolution loop."""
from __future__ import annotations

import time

from supervisor_client import Client, SupervisorError


def wait_for_review_resolution(
    client: Client,
    action_id: str,
    *,
    poll_interval_s: float,
    timeout_s: float,
) -> str:
    """Block until the review resolves. Returns the final decision string
    ("allow" when the reviewer approved, "deny" when rejected/timed-out).

    The supervisor's /v1/decisions/{id} endpoint always returns the
    original decision (which is "review" here) until the review is
    resolved. We poll /v1/review-cases?status=... and match on action_id
    to detect resolution.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for status in ("approved", "rejected"):
            try:
                rows = client.list_reviews(status)  # type: ignore[arg-type]
            except SupervisorError:
                rows = []
            if any(r.action_id == action_id for r in rows):
                return "allow" if status == "approved" else "deny"
        time.sleep(poll_interval_s)
    return "deny"  # timeout → treat as rejected, safer default
