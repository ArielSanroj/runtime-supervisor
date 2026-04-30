"""Tests for the scope_guard.base.v1 policy.

Pinned to the Andrea/Prodesa scenario: a chatbot's LLM mentioned
`Pablo`, `Garbett`, `Lina`, `Cristina`, and `Mercelena`, none of whom
were in the user's authorized `team_members`. The policy must deny the
response from passing through.
"""
from pathlib import Path

from supervisor_api.engines.policy import evaluate, load_policy, worst_action

REPO_ROOT = Path(__file__).resolve().parents[4]
POLICY = REPO_ROOT / "packages/policies/scope_guard.base.v1.yaml"


def test_andrea_pablo_regression_triggers_deny():
    policy = load_policy(POLICY)
    payload = {
        "entities_mentioned": ["Andrea", "Pablo", "Garbett"],
        "allowed_entities": ["Andrea", "Karen", "Laura"],
    }
    hits = evaluate(policy, payload)
    assert any(h.rule_id == "deny-out-of-scope-entity" and h.action == "deny" for h in hits)
    assert worst_action(hits) == "deny"


def test_all_entities_in_scope_passes_clean():
    policy = load_policy(POLICY)
    payload = {
        "entities_mentioned": ["Andrea", "Karen"],
        "allowed_entities": ["Andrea", "Karen", "Laura"],
    }
    hits = evaluate(policy, payload)
    # No hits → response goes through. The entity-set is a subset of allowed.
    assert hits == []


def test_no_entities_mentioned_passes_clean():
    """A response that names no one (e.g., a generic answer) must not
    trip either rule. The policy is for scoping references, not for
    requiring that responses be name-free."""
    policy = load_policy(POLICY)
    payload = {
        "entities_mentioned": [],
        "allowed_entities": ["Andrea", "Karen", "Laura"],
    }
    hits = evaluate(policy, payload)
    assert hits == []


def test_empty_allowed_with_mentions_triggers_review():
    """Wiring bug: the wrapper forgot to thread the user's scope into
    the payload. The review-class rule surfaces this so it doesn't
    silently mask hallucinations behind a permissive default."""
    policy = load_policy(POLICY)
    payload = {
        "entities_mentioned": ["Andrea"],
        "allowed_entities": [],
    }
    hits = evaluate(policy, payload)
    assert any(h.rule_id == "review-empty-allowed-with-mentions" and h.action == "review" for h in hits)


def test_empty_payload_passes_clean():
    """Missing fields should default to empty lists (the rules use
    payload.get with a default). Treats the policy as forward-compatible
    with callers who haven't migrated to the new payload shape."""
    policy = load_policy(POLICY)
    hits = evaluate(policy, {})
    assert hits == []
