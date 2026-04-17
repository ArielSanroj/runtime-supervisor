from pathlib import Path

from supervisor_api.engines.policy import evaluate, load_policy, worst_action

REPO_ROOT = Path(__file__).resolve().parents[4]
POLICY = REPO_ROOT / "packages/policies/refund.base.v1.yaml"


def test_hard_cap_triggers_deny():
    policy = load_policy(POLICY)
    hits = evaluate(policy, {"amount": 20000})
    assert any(h.rule_id == "hard-cap" and h.action == "deny" for h in hits)


def test_negative_amount_triggers_deny():
    policy = load_policy(POLICY)
    hits = evaluate(policy, {"amount": -1})
    assert any(h.rule_id == "negative-amount" for h in hits)


def test_fraud_reason_triggers_review():
    policy = load_policy(POLICY)
    hits = evaluate(policy, {"amount": 10, "reason": "fraud_dispute"})
    assert any(h.action == "review" for h in hits)


def test_clean_payload_has_no_hits():
    policy = load_policy(POLICY)
    hits = evaluate(policy, {"amount": 100, "reason": "defective"})
    assert hits == []


def test_worst_action_priority():
    policy = load_policy(POLICY)
    hits = evaluate(policy, {"amount": 20000, "reason": "fraud_dispute"})
    assert worst_action(hits) == "deny"
