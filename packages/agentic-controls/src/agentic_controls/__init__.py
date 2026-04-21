"""Agentic Controls — radar for AI-agent actions.

One package. One CLI. One decorator.

Usage:

    import agentic_controls as ac

    def notify_compliance(review_case):
        # Your async channel: slack, email, Teams, whatever.
        slack.post(f"Review needed: {review_case.action_type} from {review_case.action_payload}")
        # Return None to leave pending; return "approved"/"rejected" to auto-resolve.
        return None

    ac.configure(
        base_url="http://localhost:8099",
        app_id="...",
        shared_secret="...",
        on_review=notify_compliance,
    )

    @ac.supervised("payment")
    def create_checkout(amount, customer_id): ...

CLI:
    ac start        → launches the supervisor + UI locally (one process tree)
    ac scan         → scans the current repo and generates runtime-supervisor/
    ac review       → opens the review queue in the browser
    ac stop         → stops local services
    ac status       → shows what's running
"""

from __future__ import annotations

# Re-export the core primitives so callers only ever import from `agentic_controls`.
from supervisor_guards import (
    SupervisorBlocked,
    SupervisorReviewPending,
    configure,
    get_client,
    guarded,
    observe,
    observing,
    supervised,
    supervised_async,
)

from .review_daemon import ReviewCase, set_on_review

__all__ = [
    "SupervisorBlocked",
    "SupervisorReviewPending",
    "ReviewCase",
    "configure",
    "get_client",
    "guarded",
    "observe",
    "observing",
    "set_on_review",
    "supervised",
    "supervised_async",
]

__version__ = "0.1.0"
