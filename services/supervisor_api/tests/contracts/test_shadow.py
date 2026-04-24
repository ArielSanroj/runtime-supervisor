"""Contract: POST /v1/actions/evaluate with shadow=true + /v1/metrics/enforcement."""
from __future__ import annotations

_PAYLOAD_ALLOW = {
    "amount": 50, "customer_id": "c-shadow-1", "currency": "USD",
    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective",
}

_PAYLOAD_HARDCAP = {
    "amount": 20000, "customer_id": "c-shadow-2", "currency": "USD",
    "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective",
}


def test_evaluate_shadow_returns_allow_with_would_have(client):
    """Shadow request that WOULD have denied (hard-cap) comes back as allow
    but shadow_would_have='deny'."""
    r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": _PAYLOAD_HARDCAP, "shadow": True,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "allow"
    assert d["shadow_would_have"] == "deny"


def test_evaluate_shadow_allow_has_no_would_have_mismatch(client):
    """A shadow call whose real decision is allow still carries
    shadow_would_have='allow' (so clients can always branch on it)."""
    r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": _PAYLOAD_ALLOW, "shadow": True,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["decision"] == "allow"
    assert d["shadow_would_have"] == "allow"


def test_evaluate_non_shadow_sets_would_have_null(client):
    """Non-shadow calls leave shadow_would_have as null."""
    r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": _PAYLOAD_ALLOW,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["shadow_would_have"] is None


def test_shadow_does_not_create_review_item(client):
    """Shadow evaluation that would have gone to review does NOT create a
    ReviewItem — there's no human to bother in shadow mode."""
    review_payload = {
        "amount": 1200, "customer_id": "c-shadow-3", "currency": "USD",
        "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind",
    }
    # Sanity: this payload actually triggers review in enforce mode
    enforce_r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": review_payload,
    })
    assert enforce_r.json()["decision"] == "review"

    # Same payload, shadow=true → decision=allow, shadow_would_have=review, no new ReviewItem
    before = client.get("/v1/review-cases?status=pending").json()
    shadow_r = client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": review_payload, "shadow": True,
    })
    assert shadow_r.json()["decision"] == "allow"
    assert shadow_r.json()["shadow_would_have"] == "review"
    after = client.get("/v1/review-cases?status=pending").json()
    assert len(after) == len(before)


def test_metrics_enforcement_counts_shadow_vs_enforce(client):
    """Metrics endpoint separates shadow from enforced evaluations and
    reports would_block_in_shadow for the shadow hard-cap case."""
    # Two shadow hard-cap calls → would_block_in_shadow should be >= 2
    for _ in range(2):
        client.post("/v1/actions/evaluate", json={
            "action_type": "refund", "payload": _PAYLOAD_HARDCAP, "shadow": True,
        })
    # One enforced allow
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": _PAYLOAD_ALLOW,
    })
    # One enforced deny (hard-cap)
    client.post("/v1/actions/evaluate", json={
        "action_type": "refund", "payload": _PAYLOAD_HARDCAP,
    })

    r = client.get("/v1/metrics/enforcement?window=24h")
    assert r.status_code == 200
    d = r.json()
    assert d["shadow_evaluations"] >= 2
    assert d["enforced_evaluations"] >= 2
    assert d["would_block_in_shadow"] >= 2
    assert d["actually_blocked"] >= 1
    # Latency reported from at least one sample
    assert d["latency_ms"]["samples"] >= 1


def test_metrics_enforcement_rejects_bad_window(client):
    r = client.get("/v1/metrics/enforcement?window=99y")
    assert r.status_code == 422
