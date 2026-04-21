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

OnReview = Literal["block", "fail_closed", "fail_open", "shadow"]
EnforcementMode = Literal["shadow", "sample", "enforce"]

_lock = Lock()
_client: Client | None = None
_default_on_review: OnReview = "block"
_review_poll_interval_s: float = 2.0
_review_timeout_s: float = 60.0
_enforcement_mode: EnforcementMode = "shadow"
_sample_percent: int = 10
_app_id: str = ""


def configure(
    base_url: str | None = None,
    app_id: str | None = None,
    shared_secret: str | None = None,
    scopes: list[str] | None = None,
    *,
    default_on_review: OnReview = "block",
    review_poll_interval_seconds: float = 2.0,
    review_timeout_seconds: float = 60.0,
    enforcement_mode: EnforcementMode | None = None,
    sample_percent: int | None = None,
) -> None:
    """Call once at app startup. All args fall back to env vars if omitted.

    Env vars:
      SUPERVISOR_BASE_URL, SUPERVISOR_APP_ID, SUPERVISOR_SECRET, SUPERVISOR_SCOPES (comma-separated),
      SUPERVISOR_ENFORCEMENT_MODE (shadow|sample|enforce), SUPERVISOR_SAMPLE_PERCENT (int 0-100)

    Default `enforcement_mode` is `"shadow"` — guards call evaluate() and
    log the decision, but never block. Flip to `"enforce"` once the shadow
    metrics look good; use `"sample"` + `sample_percent=N` to roll out
    gradually to N% of traffic.
    """
    global _client, _default_on_review, _review_poll_interval_s, _review_timeout_s
    global _enforcement_mode, _sample_percent, _app_id
    with _lock:
        resolved_app_id = app_id or os.environ.get("SUPERVISOR_APP_ID", "")
        _client = Client(
            base_url=base_url or os.environ.get("SUPERVISOR_BASE_URL", "http://localhost:8000"),
            app_id=resolved_app_id,
            shared_secret=shared_secret or os.environ.get("SUPERVISOR_SECRET", ""),
            scopes=scopes or [s for s in os.environ.get("SUPERVISOR_SCOPES", "*").split(",") if s],
        )
        _app_id = resolved_app_id
        _default_on_review = default_on_review
        _review_poll_interval_s = review_poll_interval_seconds
        _review_timeout_s = review_timeout_seconds
        env_mode = os.environ.get("SUPERVISOR_ENFORCEMENT_MODE")
        if enforcement_mode is not None:
            _enforcement_mode = enforcement_mode
        elif env_mode in ("shadow", "sample", "enforce"):
            _enforcement_mode = env_mode  # type: ignore[assignment]
        else:
            _enforcement_mode = "shadow"
        if sample_percent is not None:
            _sample_percent = max(0, min(100, int(sample_percent)))
        else:
            try:
                _sample_percent = max(0, min(100, int(os.environ.get("SUPERVISOR_SAMPLE_PERCENT", "10"))))
            except ValueError:
                _sample_percent = 10


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


def get_enforcement_mode() -> EnforcementMode:
    return _enforcement_mode


def get_sample_percent() -> int:
    return _sample_percent


def get_app_id() -> str:
    return _app_id


def reset_for_tests() -> None:
    """Tests use this to inject a pre-built Client."""
    global _client, _enforcement_mode, _sample_percent, _default_on_review, _app_id
    with _lock:
        _client = None
        _enforcement_mode = "shadow"
        _sample_percent = 10
        _default_on_review = "block"
        _app_id = ""


def inject_client_for_tests(
    client: Client,
    *,
    enforcement_mode: EnforcementMode = "enforce",
    sample_percent: int = 10,
    default_on_review: OnReview = "block",
    app_id: str = "test-app",
) -> None:
    global _client, _enforcement_mode, _sample_percent, _default_on_review, _app_id
    with _lock:
        _client = client
        _enforcement_mode = enforcement_mode
        _sample_percent = sample_percent
        _default_on_review = default_on_review
        _app_id = app_id
