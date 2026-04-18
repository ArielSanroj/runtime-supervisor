"""Startup bootstrap: seed DB policies from disk YAML when DB is empty."""
from __future__ import annotations


def test_seed_populates_policies_for_live_action_types(client):
    from supervisor_api.bootstrap import seed_policies_from_yaml

    seeded = seed_policies_from_yaml()
    assert "refund" in seeded
    assert "payment" in seeded

    rows = client.get("/v1/policies?active_only=true", headers={"X-Admin-Token": "test-admin-token"}).json()
    ids = {r["action_type"]: r for r in rows}
    assert ids["refund"]["is_active"] is True
    assert ids["refund"]["created_by"] == "bootstrap"
    assert ids["payment"]["is_active"] is True


def test_seed_is_idempotent(client):
    from supervisor_api.bootstrap import seed_policies_from_yaml

    first = seed_policies_from_yaml()
    second = seed_policies_from_yaml()
    assert first  # something seeded on first call
    assert second == []  # nothing seeded on second call


def test_seed_does_not_override_admin_created_policies(client):
    ADMIN = {"X-Admin-Token": "test-admin-token"}
    custom_yaml = "name: refund.custom\nversion: 1\nrules:\n  - {id: r, when: 'False', action: deny, reason: x}\n"
    created = client.post("/v1/policies", headers=ADMIN, json={
        "action_type": "refund", "yaml_source": custom_yaml, "promote": True,
    }).json()

    from supervisor_api.bootstrap import seed_policies_from_yaml
    seeded = seed_policies_from_yaml()
    assert "refund" not in seeded  # refund already has a row

    active = client.get("/v1/policies?action_type=refund&active_only=true", headers=ADMIN).json()
    assert len(active) == 1
    assert active[0]["id"] == created["id"]
    assert active[0]["created_by"] != "bootstrap"
