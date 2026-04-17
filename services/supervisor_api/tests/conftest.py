from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_PATH = REPO_ROOT / "packages/policies/refund.base.v1.yaml"


@pytest.fixture(scope="session", autouse=True)
def _env() -> Iterator[None]:
    tmpdir = tempfile.mkdtemp(prefix="aic-test-")
    db_path = Path(tmpdir) / "test.sqlite3"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["POLICY_PATH"] = str(POLICY_PATH)
    os.environ["EVIDENCE_HMAC_SECRET"] = "test-secret"
    os.environ["APP_ENV"] = "test"
    os.environ["REQUIRE_AUTH"] = "false"
    os.environ["ADMIN_BOOTSTRAP_TOKEN"] = "test-admin-token"
    os.environ["WEBHOOK_SECRET"] = "test-webhook-secret"
    yield


@pytest.fixture()
def client() -> Iterator[TestClient]:
    # Import lazily so env vars above are picked up before Settings initializes.
    from supervisor_api.config import get_settings
    from supervisor_api.db import Base, engine
    from supervisor_api.main import app
    from supervisor_api.routes import actions as actions_route

    get_settings.cache_clear()
    actions_route._policy.cache_clear()
    # Reset schema between tests for isolation.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as c:
        yield c
