"""Public demo: anonymous callers may hit POST /v1/actions/evaluate?dry_run=true
when PUBLIC_DEMO_ENABLED is true. Everything else stays gated."""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def auth_on():
    from supervisor_api.config import get_settings

    os.environ["REQUIRE_AUTH"] = "true"
    get_settings.cache_clear()
    yield
    os.environ["REQUIRE_AUTH"] = "false"
    get_settings.cache_clear()


@pytest.fixture()
def demo_off():
    from supervisor_api.config import get_settings

    os.environ["PUBLIC_DEMO_ENABLED"] = "false"
    get_settings.cache_clear()
    yield
    os.environ.pop("PUBLIC_DEMO_ENABLED", None)
    get_settings.cache_clear()


REFUND_PAYLOAD = {
    "action_type": "refund",
    "payload": {
        "amount": 50, "customer_id": "anon", "currency": "USD",
        "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective",
    },
}


def test_anon_dry_run_allowed_when_demo_enabled(client, auth_on):
    r = client.post("/v1/actions/evaluate?dry_run=true", json=REFUND_PAYLOAD)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action_id"] == "dry-run"
    assert body["decision"] in {"allow", "review", "deny"}


def test_anon_live_evaluate_still_requires_auth(client, auth_on):
    r = client.post("/v1/actions/evaluate", json=REFUND_PAYLOAD)
    assert r.status_code == 401, r.text


def test_anon_dry_run_rejected_when_demo_disabled(client, auth_on, demo_off):
    r = client.post("/v1/actions/evaluate?dry_run=true", json=REFUND_PAYLOAD)
    assert r.status_code == 401, r.text


def test_anon_dry_run_rate_limited_per_ip(client, auth_on):
    from supervisor_api import ratelimit

    ratelimit.reset()
    # Default public_demo_rate_limit_per_minute is 10; 11th should trip.
    for i in range(10):
        r = client.post("/v1/actions/evaluate?dry_run=true", json=REFUND_PAYLOAD)
        assert r.status_code == 200, f"req {i}: {r.text}"
    r = client.post("/v1/actions/evaluate?dry_run=true", json=REFUND_PAYLOAD)
    assert r.status_code == 429, r.text
