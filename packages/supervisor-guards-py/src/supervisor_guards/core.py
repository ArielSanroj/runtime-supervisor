"""Core decorators + imperative guard function.

`@supervised` wraps a function so that BEFORE it runs, the supervisor
evaluates the captured payload. Deny → raises SupervisorBlocked. Review →
per `on_review` policy. Allow → runs the wrapped function.

The payload extractor is a lambda so callers keep control of what's
visible to the supervisor (don't leak secrets). Defaults to a safe
capture of positional + keyword args stringified.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from .config import (
    OnReview,
    get_client,
    get_default_on_review,
    get_review_poll_interval,
    get_review_timeout,
)
from .errors import SupervisorBlocked, SupervisorReviewPending
from .polling import wait_for_review_resolution

log = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])
AF = TypeVar("AF", bound=Callable[..., Awaitable[Any]])


def _default_payload(args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    return {"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}}


def _pre_check(
    action_type: str,
    payload: dict[str, Any],
    on_review: OnReview | None,
) -> str | None:
    """Runs the sync pre-call. Returns the action_id to attach to the result
    (None when dry-flow isn't needed). Raises on deny or review timeout.
    """
    client = get_client()
    mode: OnReview = on_review or get_default_on_review()
    dec = client.evaluate(action_type, payload)

    if dec.allowed:
        return dec.action_id
    if dec.blocked:
        raise SupervisorBlocked(
            decision="deny", reasons=dec.reasons, action_id=dec.action_id, threats=[],
        )
    # review
    if mode == "fail_open":
        log.warning("supervisor review on %s (action_id=%s), proceeding (fail_open)", action_type, dec.action_id)
        return dec.action_id
    if mode == "fail_closed":
        raise SupervisorReviewPending(action_id=dec.action_id, reasons=dec.reasons)
    # mode == "block" → poll for resolution
    resolved = wait_for_review_resolution(
        client, dec.action_id,
        poll_interval_s=get_review_poll_interval(),
        timeout_s=get_review_timeout(),
    )
    if resolved == "allow":
        return dec.action_id
    raise SupervisorBlocked(
        decision="deny", reasons=["review-rejected-or-timed-out"], action_id=dec.action_id,
    )


def supervised(
    action_type: str,
    *,
    payload: Callable[..., dict[str, Any]] | None = None,
    on_review: OnReview | None = None,
) -> Callable[[F], F]:
    """Decorator for sync functions."""
    extractor = payload or (lambda *a, **kw: _default_payload(a, kw))

    def deco(fn: F) -> F:
        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            p = extractor(*args, **kwargs)
            _pre_check(action_type, p, on_review)
            return fn(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return deco


def supervised_async(
    action_type: str,
    *,
    payload: Callable[..., dict[str, Any]] | None = None,
    on_review: OnReview | None = None,
) -> Callable[[AF], AF]:
    """Decorator for async functions. Pre-check runs in a thread so it can
    still poll synchronously without blocking the event loop."""
    extractor = payload or (lambda *a, **kw: _default_payload(a, kw))

    def deco(fn: AF) -> AF:
        @functools.wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            p = extractor(*args, **kwargs)
            await asyncio.to_thread(_pre_check, action_type, p, on_review)
            return await fn(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return deco


def guarded(
    action_type: str,
    payload: dict[str, Any],
    fn: Callable[..., Any],
    *args: Any,
    on_review: OnReview | None = None,
    **kwargs: Any,
) -> Any:
    """Imperative form — call where a decorator would be awkward."""
    _pre_check(action_type, payload, on_review)
    return fn(*args, **kwargs)
