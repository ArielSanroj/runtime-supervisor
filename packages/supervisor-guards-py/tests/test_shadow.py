"""Shadow / sample / enforce behavior tests.

These go against a real supervisor so the server-side shadow bifurcation
(no ReviewItem, no execute, returns allow with shadow_would_have) is also
exercised end-to-end.
"""
from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_PATH = REPO_ROOT / "packages/policies/refund.base.v1.yaml"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def supervisor_url():
    tmpdir = tempfile.mkdtemp(prefix="shadow-test-")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/test.sqlite3"
    os.environ["POLICY_PATH"] = str(POLICY_PATH)
    os.environ["EVIDENCE_HMAC_SECRET"] = "test"
    os.environ["REQUIRE_AUTH"] = "true"
    os.environ["ADMIN_BOOTSTRAP_TOKEN"] = "admin"
    os.environ["SUPERVISOR_SKIP_SEED"] = "true"
    os.environ["LOG_JSON"] = "false"

    from supervisor_api.config import get_settings
    from supervisor_api.db import Base, engine
    from supervisor_api.main import app

    get_settings.cache_clear()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _create_integration(base_url: str, scopes: list[str], name: str) -> dict:
    with httpx.Client(base_url=base_url, timeout=5.0) as c:
        r = c.post("/v1/integrations", headers={"X-Admin-Token": "admin"},
                   json={"name": name, "scopes": scopes})
        r.raise_for_status()
        return r.json()


def _make_client(base_url: str):
    from supervisor_client import Client

    integ = _create_integration(base_url, ["refund"], f"shadow-{time.time_ns()}")
    return Client(base_url=base_url, app_id=integ["id"],
                  shared_secret=integ["shared_secret"], scopes=["refund"])


_HARDCAP_PAYLOAD = {
    "amount": 20000, "currency": "USD", "customer_id": "c-shadow",
    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective",
}


def test_shadow_mode_never_blocks_even_on_hard_cap(supervisor_url):
    """With enforcement_mode="shadow", a payload that hits the hard-cap
    still lets the wrapped function run. The server knows the call was
    shadow and reports the would-have on the response."""
    from supervisor_guards import supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="shadow")
    try:
        ran = {"n": 0}

        @supervised("refund", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            ran["n"] += 1
            return "ran"

        out = issue_refund()
        assert out == "ran"
        assert ran["n"] == 1
    finally:
        reset_for_tests()


def test_shadow_client_sends_shadow_true_to_server(supervisor_url):
    """Direct client call with shadow=True → server returns allow +
    shadow_would_have populated with the real decision."""
    client = _make_client(supervisor_url)
    dec = client.evaluate("refund", _HARDCAP_PAYLOAD, shadow=True)
    assert dec.decision == "allow"
    assert dec.shadow_would_have == "deny"


def test_enforce_mode_still_blocks(supervisor_url):
    """Sanity check: switching back to enforce_mode reinstates blocking."""
    from supervisor_guards import SupervisorBlocked, supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="enforce")
    try:

        @supervised("refund", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            raise AssertionError("decorator did not block")

        with pytest.raises(SupervisorBlocked):
            issue_refund()
    finally:
        reset_for_tests()


def test_per_wrapper_shadow_override_beats_enforce(supervisor_url):
    """Global enforcement_mode="enforce" but on_review="shadow" per-wrapper
    → the wrapper still runs shadow (never blocks)."""
    from supervisor_guards import supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="enforce")
    try:
        ran = {"n": 0}

        @supervised("refund", on_review="shadow", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            ran["n"] += 1

        issue_refund()
        assert ran["n"] == 1
    finally:
        reset_for_tests()


def test_sample_mode_mixes_shadow_and_enforce(supervisor_url):
    """enforcement_mode="sample" with sample_percent=50: over N calls, some
    enforce (hardcap raises) and some shadow (runs). We don't assert exact
    counts — the hash is random per call — just that BOTH paths appear."""
    from supervisor_guards import SupervisorBlocked, supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="sample", sample_percent=50)
    try:
        ran = {"n": 0}
        blocked = 0

        @supervised("refund", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            ran["n"] += 1

        # 20 tries should exercise both paths with overwhelming probability.
        for _ in range(20):
            try:
                issue_refund()
            except SupervisorBlocked:
                blocked += 1

        assert ran["n"] > 0, "sample=50% should let some calls through as shadow"
        assert blocked > 0, "sample=50% should enforce some calls"
    finally:
        reset_for_tests()


def test_sample_zero_percent_always_shadows(supervisor_url):
    from supervisor_guards import supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="sample", sample_percent=0)
    try:
        ran = {"n": 0}

        @supervised("refund", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            ran["n"] += 1

        for _ in range(5):
            issue_refund()
        assert ran["n"] == 5
    finally:
        reset_for_tests()


def test_sample_hundred_percent_always_enforces(supervisor_url):
    from supervisor_guards import SupervisorBlocked, supervised
    from supervisor_guards.config import inject_client_for_tests, reset_for_tests

    client = _make_client(supervisor_url)
    inject_client_for_tests(client, enforcement_mode="sample", sample_percent=100)
    try:

        @supervised("refund", payload=lambda **kw: _HARDCAP_PAYLOAD)
        def issue_refund(**kwargs):
            raise AssertionError("decorator did not block")

        for _ in range(5):
            with pytest.raises(SupervisorBlocked):
                issue_refund()
    finally:
        reset_for_tests()
