"""Payment supervisor end-to-end."""
from __future__ import annotations

from typing import Any


def _evaluate(client, payload: dict[str, Any]) -> dict[str, Any]:
    r = client.post("/v1/actions/evaluate", json={"action_type": "payment", "payload": payload})
    assert r.status_code == 200, r.text
    return r.json()


def test_benign_payment_is_allowed(client):
    out = _evaluate(client, {
        "amount": 500, "currency": "USD", "vendor_id": "v1",
        "vendor_first_seen_days": 400, "approval_chain": ["finance_manager"],
        "bank_account_changed": False, "beneficiary_country": "US",
    })
    assert out["decision"] == "allow"
    assert out["risk_score"] == 0


def test_large_amount_with_new_vendor_reviews(client):
    out = _evaluate(client, {
        "amount": 15000, "currency": "USD", "vendor_id": "v2",
        "vendor_first_seen_days": 5, "approval_chain": ["finance_manager", "cfo"],
        "bank_account_changed": False, "beneficiary_country": "US",
    })
    # amount-over-10k (+30) + new-vendor (+30) = 60 → review
    assert out["decision"] == "review"
    assert out["risk_score"] == 60


def test_bank_account_changed_on_mid_amount_is_review(client):
    out = _evaluate(client, {
        "amount": 6000, "currency": "USD", "vendor_id": "v3",
        "vendor_first_seen_days": 400, "approval_chain": ["finance_manager"],
        "bank_account_changed": True, "beneficiary_country": "US",
    })
    # policy rule bank-account-changed-on-large-amount → review
    assert out["decision"] == "review"
    assert any(r == "bank-account-changed-mid-amount" for r in out["reasons"])


def test_huge_amount_denies(client):
    out = _evaluate(client, {
        "amount": 500000, "currency": "USD", "vendor_id": "v4",
        "vendor_first_seen_days": 400, "approval_chain": ["finance_manager", "cfo"],
        "bank_account_changed": False, "beneficiary_country": "US",
    })
    assert out["decision"] == "deny"
    assert "amount-exceeds-hard-cap" in out["reasons"]


def test_missing_approval_chain_on_large_amount_denies(client):
    out = _evaluate(client, {
        "amount": 60000, "currency": "USD", "vendor_id": "v5",
        "vendor_first_seen_days": 400, "approval_chain": [],
        "bank_account_changed": False, "beneficiary_country": "US",
    })
    assert out["decision"] == "deny"
    assert "missing-approval-chain-on-large-amount" in out["reasons"]


def test_sanctioned_country_denies(client):
    out = _evaluate(client, {
        "amount": 100, "currency": "USD", "vendor_id": "v6",
        "vendor_first_seen_days": 400, "approval_chain": ["finance_manager"],
        "bank_account_changed": False, "beneficiary_country": "KP",
    })
    assert out["decision"] == "deny"
    assert "sanctioned-country" in out["reasons"]


def test_negative_amount_denies(client):
    out = _evaluate(client, {
        "amount": -100, "currency": "USD", "vendor_id": "v7",
        "vendor_first_seen_days": 400, "approval_chain": ["finance_manager"],
        "beneficiary_country": "US",
    })
    assert out["decision"] == "deny"
    assert "invalid-amount" in out["reasons"]


def test_evidence_bundle_works_for_payment(client):
    dec = _evaluate(client, {
        "amount": 15000, "currency": "USD", "vendor_id": "v8",
        "vendor_first_seen_days": 5, "approval_chain": ["finance_manager", "cfo"],
        "bank_account_changed": False, "beneficiary_country": "US",
    })
    bundle = client.get(f"/v1/decisions/{dec['action_id']}/evidence").json()
    assert bundle["chain_ok"] is True
    assert bundle["action_type"] == "payment"
    assert bundle["status"] == "pending_review"


def test_registry_catalog_shows_payment_live(client):
    spec = client.get("/v1/action-types/payment").json()
    assert spec["status"] == "live"
    assert spec["policy_ref"] == "payment.base@v1"
    assert "amount" in spec["sample_payload"]


def test_sample_payload_from_catalog_evaluates(client):
    # The landing demo uses this exact payload — it must not crash.
    spec = client.get("/v1/action-types/payment").json()
    r = client.post("/v1/actions/evaluate?dry_run=true",
                    json={"action_type": "payment", "payload": spec["sample_payload"]})
    assert r.status_code == 200
    out = r.json()
    # With amount 12000 + new vendor 14 days → 30+30=60 → review
    assert out["decision"] in ("allow", "review")  # tolerant to future tuning
