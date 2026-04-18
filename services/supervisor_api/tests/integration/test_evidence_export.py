"""Evidence bundle durable-storage export."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def _create_action(client) -> str:
    dec = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    }).json()
    return dec["action_id"]


def test_export_writes_bundle_to_local_storage(client, tmp_path):
    os.environ["STORAGE_PATH"] = str(tmp_path)
    from supervisor_api import storage
    storage.reset_backend()

    action_id = _create_action(client)
    r = client.post(f"/v1/decisions/{action_id}/evidence/export")
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["action_id"] == action_id
    assert out["url"].startswith("file://")
    assert out["bundle_hash"]
    assert out["size_bytes"] > 0

    # The file was written and contains the bundle JSON
    path = Path(out["url"].removeprefix("file://"))
    assert path.exists()
    loaded = json.loads(path.read_text())
    assert loaded["action_id"] == action_id
    assert loaded["chain_ok"] is True


def test_export_appends_evidence_event(client, tmp_path):
    os.environ["STORAGE_PATH"] = str(tmp_path)
    from supervisor_api import storage
    storage.reset_backend()

    action_id = _create_action(client)
    client.post(f"/v1/decisions/{action_id}/evidence/export")
    bundle = client.get(f"/v1/decisions/{action_id}/evidence").json()
    event_types = [e["event_type"] for e in bundle["events"]]
    assert "bundle.exported_to_blob" in event_types
    assert bundle["chain_ok"] is True


def test_export_404_on_unknown(client, tmp_path):
    os.environ["STORAGE_PATH"] = str(tmp_path)
    from supervisor_api import storage
    storage.reset_backend()
    r = client.post("/v1/decisions/nonexistent/evidence/export")
    assert r.status_code == 404
