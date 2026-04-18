"""Seed demo fixtures + create a dev integration for the control-center.

Idempotent: re-running won't duplicate the integration. If `REQUIRE_AUTH=true`,
prints the integration id + secret once so the control-center can pick them up.

Run: uv run python -m supervisor_api.seed
"""

from __future__ import annotations

import os
import sys
from datetime import UTC

from sqlalchemy import select

from . import auth
from .config import get_settings
from .db import Base, SessionLocal, engine
from .main import app
from .models import Integration

FIXTURES: list[tuple[str, dict]] = [
    ("benign", {"amount": 50, "currency": "USD", "customer_id": "c_benign", "customer_age_days": 730, "refund_velocity_24h": 0, "reason": "defective"}),
    ("borderline", {"amount": 1200, "currency": "USD", "customer_id": "c_bord", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"}),
    ("fraud-flag", {"amount": 200, "currency": "USD", "customer_id": "c_fraud", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "fraud_dispute"}),
    ("cap", {"amount": 15000, "currency": "USD", "customer_id": "c_cap", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}),
    ("invalid", {"amount": -50, "currency": "USD", "customer_id": "c_inv", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}),
]

CONTROL_CENTER_NAME = "control-center"


def ensure_control_center_integration() -> tuple[str, str | None]:
    """Create the control-center integration if missing. Returns (id, secret_if_new)."""
    db = SessionLocal()
    try:
        existing = db.execute(
            select(Integration).where(Integration.name == CONTROL_CENTER_NAME)
        ).scalar_one_or_none()
        if existing is not None:
            return existing.id, None
        secret = auth.generate_secret()
        integration = Integration(name=CONTROL_CENTER_NAME, shared_secret=secret, scopes=["*"], active=True)
        db.add(integration)
        db.commit()
        db.refresh(integration)
        return integration.id, secret
    finally:
        db.close()


def main() -> None:
    Base.metadata.create_all(bind=engine)

    cc_id, cc_secret = ensure_control_center_integration()
    if cc_secret is not None:
        print("─── control-center integration created ───")
        print(f"SUPERVISOR_APP_ID={cc_id}")
        print(f"SUPERVISOR_SECRET={cc_secret}")
        print("Paste these into apps/control-center/.env.local if REQUIRE_AUTH=true.")
        print("───────────────────────────────────────────")
    else:
        print(f"control-center integration already exists (id={cc_id})")

    # Use the FastAPI TestClient to exercise the full request path (auth + webhooks).
    # When REQUIRE_AUTH is true we need to send a JWT.
    from fastapi.testclient import TestClient

    client = TestClient(app)
    headers = {}
    if get_settings().require_auth:
        db = SessionLocal()
        try:
            integration = db.get(Integration, cc_id)
            assert integration is not None
            # Use the secret from this session if just-created; otherwise read from DB.
            secret = cc_secret or integration.shared_secret
        finally:
            db.close()
        from datetime import datetime, timedelta

        token = auth.sign_jwt(
            {
                "sub": cc_id,
                "scopes": ["*"],
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            },
            secret,
        )
        headers["Authorization"] = f"Bearer {token}"

    ok = True
    for name, payload in FIXTURES:
        r = client.post(
            "/v1/actions/evaluate",
            headers=headers,
            json={"action_type": "refund", "payload": payload},
        )
        if r.status_code != 200:
            print(f"[{name:10}] FAIL {r.status_code} {r.text}")
            ok = False
            continue
        data = r.json()
        print(f"[{name:10}] {data['decision']:6} score={data['risk_score']:<3} action_id={data['action_id']}")

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    # Respect .env in the supervisor service dir
    os.environ.setdefault("REQUIRE_AUTH", os.environ.get("REQUIRE_AUTH", "false"))
    main()
