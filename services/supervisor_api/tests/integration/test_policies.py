"""Policy editor API + loader DB-first fallback."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}

STRICTER_REFUND_YAML = """
name: refund.strict
version: 1
rules:
  - id: hard-cap
    when: "payload['amount'] > 500"
    action: deny
    reason: amount-exceeds-strict-cap
  - id: negative-amount
    when: "payload['amount'] <= 0"
    action: deny
    reason: invalid-amount
"""


def test_admin_required(client):
    r = client.post("/v1/policies", json={"action_type": "refund", "yaml_source": STRICTER_REFUND_YAML})
    assert r.status_code == 401


def test_create_policy_validates_yaml(client):
    r = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": "not: [a valid policy}",
    })
    assert r.status_code == 422


def test_create_rejects_bad_rule_action(client):
    bad = "name: x\nversion: 1\nrules:\n  - {id: r, when: 'True', action: maybe, reason: x}\n"
    r = client.post("/v1/policies", headers=ADMIN_HEADERS, json={"action_type": "refund", "yaml_source": bad})
    assert r.status_code == 422
    assert "invalid rule action" in r.json()["detail"]


def test_create_rejects_broken_when_expression(client):
    # `when: '=='` is a true syntax error (incomplete expression).
    bad = "name: x\nversion: 1\nrules:\n  - {id: r, when: '==', action: deny, reason: x}\n"
    r = client.post("/v1/policies", headers=ADMIN_HEADERS, json={"action_type": "refund", "yaml_source": bad})
    assert r.status_code == 422


def test_create_list_get_and_promote(client):
    r = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML, "promote": False,
    })
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["action_type"] == "refund"
    assert created["name"] == "refund.strict"
    assert created["version"] == 1
    assert created["is_active"] is False

    rows = client.get("/v1/policies", headers=ADMIN_HEADERS).json()
    assert any(p["id"] == created["id"] for p in rows)

    # Promote: becomes active
    promoted = client.post(f"/v1/policies/{created['id']}/promote", headers=ADMIN_HEADERS).json()
    assert promoted["is_active"] is True

    only_active = client.get("/v1/policies?action_type=refund&active_only=true", headers=ADMIN_HEADERS).json()
    assert len(only_active) == 1
    assert only_active[0]["id"] == created["id"]


def test_promote_deactivates_previous(client):
    a = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML, "promote": True,
    }).json()
    # second version
    yaml2 = STRICTER_REFUND_YAML.replace("version: 1", "version: 2")
    b = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": yaml2, "promote": True,
    }).json()
    # a should be deactivated, b active
    refetched_a = client.get(f"/v1/policies/{a['id']}", headers=ADMIN_HEADERS).json()
    refetched_b = client.get(f"/v1/policies/{b['id']}", headers=ADMIN_HEADERS).json()
    assert refetched_a["is_active"] is False
    assert refetched_a["deactivated_at"] is not None
    assert refetched_b["is_active"] is True


def test_test_endpoint_runs_dry_run(client):
    created = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML,
    }).json()
    # $1000 > 500 → deny by stricter hard cap
    r = client.post(f"/v1/policies/{created['id']}/test", headers=ADMIN_HEADERS, json={
        "payload": {"amount": 1000, "customer_id": "c1", "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] == "deny"
    assert "amount-exceeds-strict-cap" in data["reasons"]


def test_deactivate_removes_from_active(client):
    created = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML, "promote": True,
    }).json()
    client.post(f"/v1/policies/{created['id']}/deactivate", headers=ADMIN_HEADERS)
    only_active = client.get("/v1/policies?action_type=refund&active_only=true", headers=ADMIN_HEADERS).json()
    assert len(only_active) == 0


def test_db_policy_overrides_yaml_on_evaluate(client):
    # Without DB policy: $1000 refund ordinarily allowed by disk YAML (>10000 is cap).
    r1 = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 1000, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r1.json()["decision"] == "allow"

    # Promote stricter DB policy: amount > 500 denied.
    client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML, "promote": True,
    })

    r2 = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 1000, "customer_id": "c2", "currency": "USD",
                    "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r2.json()["decision"] == "deny"
    assert "amount-exceeds-strict-cap" in r2.json()["reasons"]


def test_deactivating_db_policy_falls_back_to_yaml(client):
    created = client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": STRICTER_REFUND_YAML, "promote": True,
    }).json()
    # With DB active → $1000 denied
    r1 = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 1000, "customer_id": "c1", "currency": "USD",
                    "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r1.json()["decision"] == "deny"

    # Deactivate → falls back to disk YAML which allows $1000
    client.post(f"/v1/policies/{created['id']}/deactivate", headers=ADMIN_HEADERS)
    r2 = client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": 1000, "customer_id": "c2", "currency": "USD",
                    "customer_age_days": 500, "refund_velocity_24h": 0, "reason": "defective"},
    })
    assert r2.json()["decision"] == "allow"


def test_version_auto_increments_per_action_type(client):
    yaml2 = STRICTER_REFUND_YAML.replace("version: 1", "version: 99")  # the input version is ignored
    a = client.post("/v1/policies", headers=ADMIN_HEADERS, json={"action_type": "refund", "yaml_source": STRICTER_REFUND_YAML}).json()
    b = client.post("/v1/policies", headers=ADMIN_HEADERS, json={"action_type": "refund", "yaml_source": yaml2}).json()
    assert a["version"] == 1
    assert b["version"] == 2


def test_unknown_policy_id_is_404(client):
    r = client.get("/v1/policies/nonexistent-id", headers=ADMIN_HEADERS)
    assert r.status_code == 404
