"""Phase W: policy import/export."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}

SAMPLE_YAML = """\
name: imported
version: 1
rules:
  - id: cap
    when: "payload['amount'] > 777"
    action: deny
    reason: over-777
"""


def test_export_empty_returns_empty_array(client):
    r = client.get("/v1/policies/export", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json() == []


def test_export_returns_yaml_sources(client):
    client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": True,
    })
    r = client.get("/v1/policies/export", headers=ADMIN_HEADERS).json()
    assert len(r) == 1
    assert r[0]["action_type"] == "refund"
    assert "over-777" in r[0]["yaml_source"]


def test_export_active_only_filters(client):
    client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": False,
    })
    client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": SAMPLE_YAML.replace("version: 1", "version: 2"),
        "promote": True,
    })
    all_rows = client.get("/v1/policies/export", headers=ADMIN_HEADERS).json()
    active = client.get("/v1/policies/export?active_only=true", headers=ADMIN_HEADERS).json()
    assert len(all_rows) == 2
    assert len(active) == 1
    assert active[0]["version"] == 2


def test_import_creates_policies(client):
    r = client.post("/v1/policies/import", headers=ADMIN_HEADERS, json=[
        {"action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": True},
        {"action_type": "payment", "yaml_source": SAMPLE_YAML.replace("imported", "imported-pay"),
         "promote": False},
    ])
    assert r.status_code == 200
    result = r.json()
    assert result["imported"] == 2
    assert result["promoted"] == 1
    assert result["errors"] == []
    assert len(result["policy_ids"]) == 2


def test_import_collects_errors_without_blocking_valid_ones(client):
    r = client.post("/v1/policies/import", headers=ADMIN_HEADERS, json=[
        {"action_type": "refund", "yaml_source": "this is: not valid", "promote": False},
        {"action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": True},
    ]).json()
    assert r["imported"] == 1
    assert r["promoted"] == 1
    assert len(r["errors"]) == 1
    assert r["errors"][0]["index"] == 0


def test_import_audits_each_policy(client):
    client.post("/v1/policies/import", headers=ADMIN_HEADERS, json=[
        {"action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": True},
    ])
    events = client.get("/v1/admin/events?action=policy.import", headers=ADMIN_HEADERS).json()
    assert len(events) == 1


def test_export_requires_admin(client):
    r = client.get("/v1/policies/export")
    assert r.status_code == 401


def test_roundtrip_export_then_import(client):
    client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": SAMPLE_YAML, "promote": True,
    })
    exported = client.get("/v1/policies/export", headers=ADMIN_HEADERS).json()
    assert len(exported) == 1

    # Simulate restore into an "empty" env: convert export back to import items
    import_items = [
        {"action_type": e["action_type"], "yaml_source": e["yaml_source"], "promote": e["is_active"]}
        for e in exported
    ]
    r = client.post("/v1/policies/import", headers=ADMIN_HEADERS, json=import_items).json()
    assert r["imported"] == 1
    assert r["promoted"] == 1
