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
import hashlib
import inspect
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from .config import (
    OnReview,
    get_app_id,
    get_client,
    get_default_on_review,
    get_enforcement_mode,
    get_review_poll_interval,
    get_review_timeout,
    get_sample_percent,
)
from .context import current_context
from .errors import SupervisorBlocked, SupervisorReviewPending
from .polling import wait_for_review_resolution

log = logging.getLogger(__name__)


def _should_shadow(action_type: str) -> bool:
    """Return True if this call should run in shadow mode. Based on the
    global enforcement_mode + sample_percent. Deterministic per-call via a
    random token so the sample decision is stable across retries and can
    be logged for debugging."""
    mode = get_enforcement_mode()
    if mode == "shadow":
        return True
    if mode == "enforce":
        return False
    # mode == "sample": enforce on sample_percent % of calls, shadow on the rest.
    pct = get_sample_percent()
    if pct <= 0:
        return True
    if pct >= 100:
        return False
    token = f"{get_app_id()}:{action_type}:{uuid.uuid4()}"
    bucket = int(hashlib.sha256(token.encode()).hexdigest(), 16) % 100
    # bucket < pct → enforce (not shadow)
    return bucket >= pct

F = TypeVar("F", bound=Callable[..., Any])
AF = TypeVar("AF", bound=Callable[..., Awaitable[Any]])


def _default_payload(args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    return {"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}}


def _make_default_extractor(fn: Callable[..., Any]) -> Callable[..., dict[str, Any]]:
    # Bind by parameter name so policies that read `payload['amount']` work
    # without the dev writing an explicit `payload=` lambda. Falls back to
    # the args/kwargs blob when the signature can't be inspected (C builtins,
    # partials with mismatched arity, etc.).
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        sig = None

    def extract(*args: Any, **kwargs: Any) -> dict[str, Any]:
        base = _default_payload(args, kwargs)
        if sig is None:
            return base
        try:
            bound = sig.bind_partial(*args, **kwargs)
        except TypeError:
            return base
        bound.apply_defaults()
        named = {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}
        # Named args win over the args/kwargs fallback so policies see
        # `payload['amount']` directly. Values are sent raw (not stringified)
        # so numeric comparisons in policy rules work.
        return {**base, **named}

    return extract


def _pre_check(
    action_type: str,
    payload: dict[str, Any],
    on_review: OnReview | None,
) -> str | None:
    """Runs the sync pre-call. Returns the action_id to attach to the result
    (None when dry-flow isn't needed). Raises on deny or review timeout.

    Enforcement:
      - `on_review="shadow"` (per-wrapper) → always shadow; evaluate + return,
        never raise.
      - Else consult global `enforcement_mode`:
          * "shadow" → every call is shadow.
          * "sample" → `sample_percent`% of calls enforce; the rest are shadow.
          * "enforce" → regular block/review semantics.
    """
    client = get_client()
    mode: OnReview = on_review or get_default_on_review()
    shadow = True if mode == "shadow" else _should_shadow(action_type)
    agent_context = current_context()

    dec = client.evaluate(action_type, payload, shadow=shadow, agent_context=agent_context)

    if shadow:
        # Server returns allow in shadow mode regardless of real decision.
        # Log the would-have so ops can trace spurious blocks before flipping
        # enforcement on.
        would = getattr(dec, "shadow_would_have", None)
        if would and would != "allow":
            log.info("supervisor shadow would have %s for %s (action_id=%s)",
                     would, action_type, dec.action_id)
        return dec.action_id

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

    def deco(fn: F) -> F:
        extractor = payload or _make_default_extractor(fn)

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

    def deco(fn: AF) -> AF:
        extractor = payload or _make_default_extractor(fn)

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
