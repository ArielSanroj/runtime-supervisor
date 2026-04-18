"""Contract tests for /v1/metrics/summary + /v1/integrations/{id}/executions."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


def test_metrics_summary_shape(client):
    r = client.get("/v1/metrics/summary")
    assert r.status_code == 200
    d = r.json()
    assert set(d.keys()) >= {
        "window", "since", "actions_total", "decisions", "threats",
        "reviews", "executions", "active_integrations",
        "active_policies_by_type", "volume_by_action_type",
    }
    assert set(d["decisions"].keys()) == {"allow", "deny", "review"}
    assert set(d["threats"].keys()) >= {"total", "critical", "warn", "info", "top_detectors"}
    assert set(d["reviews"].keys()) >= {"pending", "approved", "rejected", "oldest_pending_age_minutes"}
    assert set(d["executions"].keys()) >= {"success", "failed", "pending", "success_rate", "total"}


def test_metrics_summary_rejects_bad_window(client):
    r = client.get("/v1/metrics/summary?window=2y")
    assert r.status_code == 422


def test_metrics_summary_reflects_actions(client):
    before = client.get("/v1/metrics/summary").json()["actions_total"]
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 50, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    })
    after = client.get("/v1/metrics/summary").json()
    assert after["actions_total"] == before + 1
    assert after["decisions"]["allow"] >= 1
    assert after["volume_by_action_type"].get("refund", 0) >= 1


def test_integration_executions_endpoint(client):
    integ = client.post("/v1/integrations", headers=ADMIN_HEADERS, json={"name": "metex", "scopes": ["*"]}).json()
    r = client.get(f"/v1/integrations/{integ['id']}/executions", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json() == []


def test_integration_executions_404_on_unknown(client):
    r = client.get("/v1/integrations/nonexistent/executions", headers=ADMIN_HEADERS)
    assert r.status_code == 404
