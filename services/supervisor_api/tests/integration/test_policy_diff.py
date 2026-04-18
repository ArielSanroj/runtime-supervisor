"""Policy diff: unified diff between two versions of a policy."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}

BASE = """\
name: base
version: 1
rules:
  - id: cap
    when: "payload['amount'] > 10000"
    action: deny
    reason: over-10k
"""

STRICTER = """\
name: base
version: 1
rules:
  - id: cap
    when: "payload['amount'] > 500"
    action: deny
    reason: over-500
  - id: new-rule
    when: "payload.get('reason') == 'fraud_dispute'"
    action: review
    reason: fraud-dispute-requires-human
"""


def _create(client, yaml_source: str, action_type: str = "refund") -> dict:
    return client.post(
        "/v1/policies", headers=ADMIN_HEADERS,
        json={"action_type": action_type, "yaml_source": yaml_source, "promote": False},
    ).json()


def test_diff_returns_unified_diff(client):
    v1 = _create(client, BASE)
    v2 = _create(client, STRICTER)

    r = client.get(f"/v1/policies/{v2['id']}/diff?against={v1['id']}", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["action_type"] == "refund"
    assert d["from"]["version"] == 1
    assert d["to"]["version"] == 2
    assert d["added_lines"] >= 3   # at least: new rule id/when/action/reason
    assert d["removed_lines"] >= 2
    assert "+++" in d["diff"] and "---" in d["diff"]
    assert "over-500" in d["diff"]
    assert "over-10k" in d["diff"]
    assert "new-rule" in d["diff"]


def test_diff_identical_policies_shows_no_changes(client):
    v1 = _create(client, BASE)
    v2 = _create(client, BASE)  # second create, identical source
    r = client.get(f"/v1/policies/{v2['id']}/diff?against={v1['id']}", headers=ADMIN_HEADERS).json()
    assert r["added_lines"] == 0
    assert r["removed_lines"] == 0
    assert r["diff"] == ""


def test_diff_404_on_unknown(client):
    v1 = _create(client, BASE)
    r = client.get(f"/v1/policies/{v1['id']}/diff?against=nonexistent", headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_diff_rejects_cross_action_type(client):
    refund = _create(client, BASE, "refund")
    payment = _create(client, BASE.replace("base", "payment-base"), "payment")
    r = client.get(f"/v1/policies/{payment['id']}/diff?against={refund['id']}", headers=ADMIN_HEADERS)
    assert r.status_code == 400
    assert "cross action_type" in r.json()["detail"]


def test_diff_requires_admin(client):
    v1 = _create(client, BASE)
    v2 = _create(client, STRICTER)
    r = client.get(f"/v1/policies/{v2['id']}/diff?against={v1['id']}")
    assert r.status_code == 401
