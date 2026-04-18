"""Contract tests: validate Pydantic schemas accept/reject the documented shapes.

These guard the external API contract. A contract break (renamed field, changed
type, tightened enum) should fail loudly here before it reaches a consumer.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from supervisor_api.schemas import (
    DecisionOut,
    EvaluateRequest,
    EvidenceBundle,
    EvidenceEventOut,
    ReviewItemOut,
    ReviewResolveRequest,
)

# ---------- EvaluateRequest ----------

def test_evaluate_request_accepts_refund():
    req = EvaluateRequest(action_type="refund", payload={"amount": 50})
    assert req.action_type == "refund"


def test_evaluate_request_rejects_missing_payload():
    with pytest.raises(ValidationError):
        EvaluateRequest(action_type="refund")  # type: ignore[call-arg]


def test_evaluate_endpoint_rejects_planned_action_type(client):
    # Pick any currently-planned action_type from the registry.
    r = client.post("/v1/actions/evaluate", json={"action_type": "data_access", "payload": {}})
    assert r.status_code == 501
    assert "planned" in r.json()["detail"]


def test_evaluate_endpoint_rejects_unknown_action_type(client):
    r = client.post("/v1/actions/evaluate", json={"action_type": "telepathy", "payload": {}})
    assert r.status_code == 400
    assert "unknown" in r.json()["detail"]


# ---------- DecisionOut ----------

def test_decision_out_accepts_allow():
    d = DecisionOut(action_id="a1", decision="allow", reasons=["ok"], risk_score=0, policy_version="refund.base@v1")
    assert d.decision == "allow"


def test_decision_out_rejects_invalid_decision():
    with pytest.raises(ValidationError):
        DecisionOut(action_id="a1", decision="maybe", reasons=[], risk_score=0, policy_version="v1")  # type: ignore[arg-type]


def test_decision_out_requires_all_fields():
    with pytest.raises(ValidationError):
        DecisionOut(action_id="a1", decision="allow")  # type: ignore[call-arg]


# ---------- ReviewResolveRequest ----------

def test_review_resolve_accepts_approved_and_rejected():
    ReviewResolveRequest(decision="approved")
    ReviewResolveRequest(decision="rejected", notes="ok")


def test_review_resolve_rejects_pending():
    with pytest.raises(ValidationError):
        ReviewResolveRequest(decision="pending")  # type: ignore[arg-type]


def test_review_resolve_rejects_oversized_notes():
    with pytest.raises(ValidationError):
        ReviewResolveRequest(decision="approved", notes="x" * 2001)


# ---------- EvidenceEventOut / EvidenceBundle ----------

def test_evidence_event_requires_hash_fields():
    with pytest.raises(ValidationError):
        EvidenceEventOut(
            seq=1,
            event_type="action.received",
            event_payload={},
            # prev_hash missing
            hash="abc",  # type: ignore[call-arg]
            created_at=datetime.now(UTC),
        )


def test_evidence_bundle_shape():
    ev = EvidenceEventOut(
        seq=1, event_type="action.received", event_payload={"k": "v"},
        prev_hash="0" * 64, hash="a" * 64, created_at=datetime.now(UTC),
    )
    bundle = EvidenceBundle(
        action_id="a1", action_type="refund", status="allowed",
        events=[ev], chain_ok=True, broken_at_seq=None,
        bundle_hash="b" * 64, bundle_signature="s" * 64,
        exported_at=datetime.now(UTC),
    )
    assert bundle.chain_ok is True
    assert bundle.events[0].seq == 1


def test_evidence_bundle_can_report_broken_chain():
    bundle = EvidenceBundle(
        action_id="a1", action_type="refund", status="allowed",
        events=[], chain_ok=False, broken_at_seq=3,
        bundle_hash="b" * 64, bundle_signature="s" * 64,
        exported_at=datetime.now(UTC),
    )
    assert bundle.chain_ok is False
    assert bundle.broken_at_seq == 3


# ---------- ReviewItemOut enum ----------

def test_review_item_status_is_constrained():
    base = dict(
        id="r1", action_id="a1", action_payload={}, action_type="refund",
        risk_score=0, policy_hits=[], created_at=datetime.now(UTC),
    )
    for status in ("pending", "approved", "rejected"):
        ReviewItemOut(status=status, **base)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ReviewItemOut(status="escalated", **base)  # type: ignore[arg-type]


# ---------- OpenAPI surface ----------

def test_openapi_exposes_expected_paths(client):
    spec = client.get("/openapi.json").json()
    expected = {
        "/v1/actions/evaluate",
        "/v1/decisions/{action_id}",
        "/v1/decisions/{action_id}/evidence",
        "/v1/review-cases",
        "/v1/review-cases/{review_id}",
        "/v1/review-cases/{review_id}/resolve",
    }
    assert expected.issubset(set(spec["paths"].keys()))


def test_openapi_evaluate_has_dry_run_param(client):
    spec = client.get("/openapi.json").json()
    params = spec["paths"]["/v1/actions/evaluate"]["post"].get("parameters", [])
    names = {p["name"] for p in params}
    assert "dry_run" in names
