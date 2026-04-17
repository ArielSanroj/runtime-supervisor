"""Test supervisor-client against a real uvicorn server running the FastAPI app."""
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
def supervisor_base_url():
    tmpdir = tempfile.mkdtemp(prefix="sup-sdk-test-")
    os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/test.sqlite3"
    os.environ["POLICY_PATH"] = str(POLICY_PATH)
    os.environ["EVIDENCE_HMAC_SECRET"] = "test"
    os.environ["REQUIRE_AUTH"] = "true"
    os.environ["ADMIN_BOOTSTRAP_TOKEN"] = "admin"

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
    if not server.started:
        raise RuntimeError("uvicorn failed to start")
    url = f"http://127.0.0.1:{port}"
    yield url
    server.should_exit = True
    thread.join(timeout=5)


def _create_integration(base_url: str, scopes: list[str], name_hint: str) -> dict:
    with httpx.Client(base_url=base_url, timeout=5.0) as c:
        r = c.post("/v1/integrations", headers={"X-Admin-Token": "admin"}, json={"name": f"app-{name_hint}", "scopes": scopes})
        r.raise_for_status()
        return r.json()


def test_evaluate_allow(supervisor_base_url):
    from supervisor_client import Client

    integ = _create_integration(supervisor_base_url, ["refund"], "allow")
    with Client(
        base_url=supervisor_base_url,
        app_id=integ["id"],
        shared_secret=integ["shared_secret"],
        scopes=["refund"],
    ) as sup:
        decision = sup.evaluate("refund", {
            "amount": 50, "currency": "USD", "customer_id": "c1",
            "customer_age_days": 700, "refund_velocity_24h": 0, "reason": "defective",
        })
        assert decision.allowed
        assert decision.risk_score == 0


def test_evaluate_dry_run(supervisor_base_url):
    from supervisor_client import Client

    integ = _create_integration(supervisor_base_url, ["refund"], "dry")
    with Client(
        base_url=supervisor_base_url,
        app_id=integ["id"],
        shared_secret=integ["shared_secret"],
        scopes=["refund"],
    ) as sup:
        d = sup.evaluate("refund", {"amount": 1200, "customer_age_days": 18, "refund_velocity_24h": 2, "reason": "changed_mind"}, dry_run=True)
        assert d.needs_review
        assert d.action_id == "dry-run"


def test_scope_enforcement(supervisor_base_url):
    from supervisor_client import Client, SupervisorError

    integ = _create_integration(supervisor_base_url, ["payment"], "scope")
    with Client(
        base_url=supervisor_base_url,
        app_id=integ["id"],
        shared_secret=integ["shared_secret"],
        scopes=["payment"],
    ) as sup:
        with pytest.raises(SupervisorError) as ei:
            sup.evaluate("refund", {"amount": 50})
        assert ei.value.status_code == 403


def test_list_action_types_roundtrip(supervisor_base_url):
    from supervisor_client import Client

    integ = _create_integration(supervisor_base_url, ["*"], "catalog")
    with Client(
        base_url=supervisor_base_url,
        app_id=integ["id"],
        shared_secret=integ["shared_secret"],
        scopes=["*"],
    ) as sup:
        types = sup.list_action_types()
        ids = {t["id"] for t in types}
        assert "refund" in ids
