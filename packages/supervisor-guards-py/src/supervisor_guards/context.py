"""Agent context hook — telemetry about WHO the agent is and WHAT it's doing.

Problem this solves: `guarded()` sees only the immediate call payload. The
supervisor has no way to correlate a refund with the agent that requested
it, the user that triggered the agent, the goal of the current task, or
the tools the agent was allowed to use. That's the "A. Antes de actuar"
column of the radar framework — identity, role, goal, tools, sources.

Design: contextvars (works in sync and asyncio). The user opens an
`observing(...)` block at the start of a task; every `guarded()` inside
picks up the active context and ships it alongside the payload.

    with sg.observing(
        session_id="s-123",
        user_id="u-456",
        role="cfo",
        goal="process january invoices",
        available_tools=["alegra.*", "stripe.refunds.*"],
        sources=["doc:q1-plan.pdf"],
    ):
        issue_refund(amount=500)          # guard sees context
        _personalize_template(...)         # same

Context keys are free-form — the supervisor stores the whole dict in the
evidence log. Convention: use the keys above so reviewers see consistent
cards in the UI, but add whatever your agent framework knows.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

# `None` means "no active observation" — the guard sends no agent_context.
_active_context: ContextVar[dict[str, Any] | None] = ContextVar(
    "supervisor_guards_active_context", default=None,
)


def current_context() -> dict[str, Any] | None:
    """Return the context dict the nearest enclosing `observing()` set, or
    None when outside any block. Called by `_pre_check` on every guarded call."""
    return _active_context.get()


@contextmanager
def observing(**context: Any) -> Iterator[None]:
    """Open an observation scope. Every guarded call inside this block sends
    `context` to the supervisor alongside the call payload.

    Nested `observing()` blocks merge — the inner one's keys override the
    outer one's, but outer keys not overridden survive. This lets a parent
    "task" context survive through child helper calls that add more detail.
    """
    parent = _active_context.get()
    merged = {**parent, **context} if parent else dict(context)
    token = _active_context.set(merged)
    try:
        yield
    finally:
        _active_context.reset(token)


def observe(**context: Any) -> None:
    """Imperative variant — sets the context for the current async task / thread
    without a `with` block. Use only when a context-manager doesn't fit (e.g.
    long-lived worker loop that pulls tasks from a queue). Call again to replace.

    Note: you're responsible for clearing (pass no args to clear) — prefer
    `observing()` for request-scoped work.
    """
    if context:
        parent = _active_context.get()
        _active_context.set({**parent, **context} if parent else dict(context))
    else:
        _active_context.set(None)
