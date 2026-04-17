"""Contract tests for /v1/action-types — backend is the single source of truth."""
from __future__ import annotations


def test_list_action_types_shape(client):
    r = client.get("/v1/action-types")
    assert r.status_code == 200
    data = r.json()
    assert "action_types" in data
    assert len(data["action_types"]) >= 1
    for spec in data["action_types"]:
        assert set(spec.keys()) == {"id", "title", "one_liner", "status", "intercepted_signals", "sample_payload", "policy_ref"}
        assert spec["status"] in ("live", "planned")
        assert isinstance(spec["intercepted_signals"], list)


def test_refund_is_live_and_has_sample_payload(client):
    r = client.get("/v1/action-types/refund")
    assert r.status_code == 200
    spec = r.json()
    assert spec["status"] == "live"
    assert spec["policy_ref"] == "refund.base@v1"
    assert spec["sample_payload"] is not None
    assert "amount" in spec["sample_payload"]


def test_planned_action_types_are_listed(client):
    r = client.get("/v1/action-types")
    ids = {a["id"] for a in r.json()["action_types"]}
    # Whatever ships, these should always appear on the roadmap view:
    assert {"refund", "payment", "account_change", "data_access"}.issubset(ids)


def test_unknown_action_type_is_404(client):
    r = client.get("/v1/action-types/nonexistent")
    assert r.status_code == 404


def test_sample_payload_produces_live_decision(client):
    """The refund sample payload must actually produce a valid decision when
    passed through dry_run — guarantees the landing demo works."""
    spec = client.get("/v1/action-types/refund").json()
    r = client.post("/v1/actions/evaluate?dry_run=true", json={
        "action_type": "refund",
        "payload": spec["sample_payload"],
    })
    assert r.status_code == 200
    out = r.json()
    assert out["decision"] in ("allow", "deny", "review")
    assert out["action_id"] == "dry-run"
