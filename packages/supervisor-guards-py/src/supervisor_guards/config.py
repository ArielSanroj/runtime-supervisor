"""Module-level configuration for the guards.

Users call `configure(...)` once at app startup. The decorator then pulls
the lazily-built `supervisor_client.Client` from here. Defaults come from
env vars so a simple `import supervisor_guards as sg` + decorator usage
works without explicit configure() if env is set.
"""
from __future__ import annotations

import os
from threading import Lock
from typing import Literal

from supervisor_client import Client

OnReview = Literal["block", "fail_closed", "fail_open"]

_lock = Lock()
_client: Client | None = None
_default_on_review: OnReview = "block"
_review_poll_interval_s: float = 2.0
_review_timeout_s: float = 60.0


def configure(
    base_url: str | None = None,
    app_id: str | None = None,
    shared_secret: str | None = None,
    scopes: list[str] | None = None,
    *,
    default_on_review: OnReview = "block",
    review_poll_interval_seconds: float = 2.0,
    review_timeout_seconds: float = 60.0,
) -> None:
    """Call once at app startup. All args fall back to env vars if omitted.

    Env vars:
      SUPERVISOR_BASE_URL, SUPERVISOR_APP_ID, SUPERVISOR_SECRET, SUPERVISOR_SCOPES (comma-separated)
    """
    global _client, _default_on_review, _review_poll_interval_s, _review_timeout_s
    with _lock:
        _client = Client(
            base_url=base_url or os.environ.get("SUPERVISOR_BASE_URL", "http://localhost:8000"),
            app_id=app_id or os.environ.get("SUPERVISOR_APP_ID", ""),
            shared_secret=shared_secret or os.environ.get("SUPERVISOR_SECRET", ""),
            scopes=scopes or [s for s in os.environ.get("SUPERVISOR_SCOPES", "*").split(",") if s],
        )
        _default_on_review = default_on_review
        _review_poll_interval_s = review_poll_interval_seconds
        _review_timeout_s = review_timeout_seconds


def get_client() -> Client:
    global _client
    with _lock:
        if _client is None:
            # Lazy auto-configure from env so `@supervised` works with just env vars set.
            configure()
        assert _client is not None
        return _client


def get_default_on_review() -> OnReview:
    return _default_on_review


def get_review_poll_interval() -> float:
    return _review_poll_interval_s


def get_review_timeout() -> float:
    return _review_timeout_s


def reset_for_tests() -> None:
    """Tests use this to inject a pre-built Client."""
    global _client
    with _lock:
        _client = None


def inject_client_for_tests(client: Client) -> None:
    global _client
    with _lock:
        _client = client
