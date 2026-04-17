"""Seed demo fixtures so the UI has something to look at.

Run: uv run python -m supervisor_api.seed
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from .db import Base, engine
from .main import app

FIXTURES: list[tuple[str, dict]] = [
    ("benign", {"amount": 50, "currency": "USD", "customer_id": "c_benign", "customer_age_days": 730, "refund_velocity_24h": 0, "reason": "defective"}),
    ("borderline", {"amount": 1200, "currency": "USD", "customer_id": "c_bord", "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"}),
    ("fraud-flag", {"amount": 200, "currency": "USD", "customer_id": "c_fraud", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "fraud_dispute"}),
    ("cap", {"amount": 15000, "currency": "USD", "customer_id": "c_cap", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}),
    ("invalid", {"amount": -50, "currency": "USD", "customer_id": "c_inv", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"}),
]


def main() -> None:
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    for name, payload in FIXTURES:
        r = client.post("/v1/actions/evaluate", json={"action_type": "refund", "payload": payload})
        r.raise_for_status()
        data = r.json()
        print(f"[{name:10}] {data['decision']:6} score={data['risk_score']:<3} action_id={data['action_id']}")


if __name__ == "__main__":
    main()
