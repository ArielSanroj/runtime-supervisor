"""The 4 policy templates ship from packages/policies/ and must compile +
evaluate without runtime errors. If someone edits a YAML and breaks it,
this test catches it before the scanner emits it to a customer's repo.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_api.engines.policy import compile_policy_yaml, evaluate

POLICIES_DIR = Path(__file__).resolve().parents[4] / "packages" / "policies"

_BY_ACTION_TYPE = {
    "refund": {"amount": 50, "customer_id": "c1", "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"},
    "payment": {"amount": 100, "vendor_id": "v1", "vendor_tenure_days": 300, "bank_account_changed_7d": False, "approvals": ["finance"]},
    "tool_use": {"tool": "ok.tool", "prompt": "hello"},
    "account_change": {"customer_id": "c1", "customer_age_days": 400, "new_email": "foo@example.com"},
    "data_access": {"operation": "read", "tenant_id": "t1", "projection": "name,email", "row_limit": 100},
    "compliance": {"kind": "gdpr_delete"},
}


@pytest.mark.parametrize("name", [
    "refund.base.v1",
    "payment.base.v1",
    "tool_use.base.v1",
    "account_change.base.v1",
    "data_access.base.v1",
    "compliance.base.v1",
])
def test_policy_compiles_and_evaluates(name: str):
    path = POLICIES_DIR / f"{name}.yaml"
    assert path.exists(), f"{path} missing"
    policy = compile_policy_yaml(path.read_text())
    assert policy.rules, f"{name} has no rules"
    # Each rule must carry a reason; explanation is optional but if present must be non-empty.
    for rule in policy.rules:
        assert rule.get("reason")
        if "explanation" in rule:
            assert str(rule["explanation"]).strip()
    # Evaluate with a safe sample payload — must not raise.
    action_type = name.split(".")[0]
    evaluate(policy, _BY_ACTION_TYPE.get(action_type, {}))


def test_compliance_policy_denies_everything_by_default():
    """compliance.base.v1 is a placeholder — every payload should hit the
    `default-review` rule until an operator defines real rules."""
    policy = compile_policy_yaml((POLICIES_DIR / "compliance.base.v1.yaml").read_text())
    hits = evaluate(policy, {})
    assert any(h.action == "review" for h in hits)
