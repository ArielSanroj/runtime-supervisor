"""Policy replay: re-evaluate recent actions against an alternative policy and show what would have changed."""
from __future__ import annotations

ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}

LOOSE_YAML = """
name: loose
version: 1
rules:
  - id: cap
    when: "payload['amount'] > 10000"
    action: deny
    reason: over-10k
"""

STRICT_YAML = """
name: strict
version: 1
rules:
  - id: cap
    when: "payload['amount'] > 500"
    action: deny
    reason: over-500
"""


def _promote(client, yaml_source: str) -> dict:
    return client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": yaml_source, "promote": True,
    }).json()


def _draft(client, yaml_source: str) -> dict:
    return client.post("/v1/policies", headers=ADMIN_HEADERS, json={
        "action_type": "refund", "yaml_source": yaml_source, "promote": False,
    }).json()


def _evaluate(client, amount: int, customer_id: str) -> dict:
    return client.post("/v1/actions/evaluate", json={
        "action_type": "refund",
        "payload": {"amount": amount, "customer_id": customer_id, "currency": "USD",
                    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    }).json()


def test_replay_flags_divergent_decisions(client):
    # Record 3 refunds under the loose policy
    loose = _promote(client, LOOSE_YAML)
    a1 = _evaluate(client, 100, "c1")     # would be allow under both
    a2 = _evaluate(client, 600, "c2")     # allow under loose, deny under strict
    a3 = _evaluate(client, 2000, "c3")    # allow under loose, deny under strict
    assert a1["decision"] == "allow"
    assert a2["decision"] == "allow"
    assert a3["decision"] == "allow"

    # Draft a stricter policy, do NOT promote
    strict = _draft(client, STRICT_YAML)

    r = client.post(f"/v1/policies/{strict['id']}/replay?window=24h", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["total"] == 3
    assert result["same"] == 1
    assert result["differ"] == 2
    assert result["would_tighten"] == 2
    assert result["would_loosen"] == 0
    assert len(result["divergences"]) == 2
    ids = {d["action_id"] for d in result["divergences"]}
    assert {a2["action_id"], a3["action_id"]} == ids
    for d in result["divergences"]:
        assert d["from_decision"] == "allow"
        assert d["to_decision"] == "deny"
        assert "over-500" in d["to_reasons"]

    # Loose policy is unchanged, not just promoted
    assert loose["is_active"] is True


def test_replay_on_empty_window_returns_zeroes(client):
    draft = _draft(client, STRICT_YAML)
    r = client.post(f"/v1/policies/{draft['id']}/replay?window=24h", headers=ADMIN_HEADERS).json()
    assert r["total"] == 0
    assert r["same"] == 0
    assert r["differ"] == 0
    assert r["divergences"] == []


def test_replay_rejects_bad_window(client):
    draft = _draft(client, STRICT_YAML)
    r = client.post(f"/v1/policies/{draft['id']}/replay?window=5m", headers=ADMIN_HEADERS)
    assert r.status_code == 422


def test_replay_404_on_unknown_policy(client):
    r = client.post("/v1/policies/nonexistent/replay?window=24h", headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_replay_looser_policy_shows_loosen(client):
    # Start strict, then draft looser → replay should show would_loosen
    _promote(client, STRICT_YAML)
    a1 = _evaluate(client, 100, "c1")     # allow under strict (under 500) → allow
    a2 = _evaluate(client, 800, "c2")     # deny under strict → would be allow under loose
    assert a1["decision"] == "allow"
    assert a2["decision"] == "deny"

    loose_draft = _draft(client, LOOSE_YAML)
    r = client.post(f"/v1/policies/{loose_draft['id']}/replay?window=24h", headers=ADMIN_HEADERS).json()
    assert r["would_loosen"] == 1
    assert r["would_tighten"] == 0
    assert r["differ"] == 1
