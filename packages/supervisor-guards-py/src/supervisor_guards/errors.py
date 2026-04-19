from __future__ import annotations

from typing import Any


class SupervisorBlocked(Exception):
    """Raised when the supervisor denies the action or a review is rejected/timed-out.

    Attributes:
        decision: "deny" | "review"
        reasons: list of policy/threat reasons
        action_id: supervisor-assigned id (for log correlation)
        threats: list of threat signals (may be empty)
    """

    def __init__(self, decision: str, reasons: list[str], action_id: str | None = None, threats: list[dict[str, Any]] | None = None) -> None:
        self.decision = decision
        self.reasons = reasons
        self.action_id = action_id
        self.threats = threats or []
        super().__init__(f"supervisor {decision}: {', '.join(reasons) or '(no reasons)'}")


class SupervisorReviewPending(Exception):
    """Raised when on_review='fail_closed' and the action requires human review."""

    def __init__(self, action_id: str, reasons: list[str]) -> None:
        self.action_id = action_id
        self.reasons = reasons
        super().__init__(f"review pending for action {action_id}: {', '.join(reasons)}")
