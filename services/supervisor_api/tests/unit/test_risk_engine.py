from supervisor_api.engines.risk import needs_review, score


def test_clean_low_amount_is_zero():
    total, breakdown = score({"amount": 50, "customer_age_days": 400, "refund_velocity_24h": 0, "reason": "defective"})
    assert total == 0
    assert breakdown == []
    assert needs_review(total) is False


def test_borderline_hits_threshold():
    total, _ = score({"amount": 1200, "customer_age_days": 10, "refund_velocity_24h": 0, "reason": "changed_mind"})
    # 30 (amount>1000) + 20 (age<30) = 50
    assert total == 50
    assert needs_review(total) is True


def test_velocity_dominates():
    total, breakdown = score({"amount": 100, "refund_velocity_24h": 5, "reason": "defective", "customer_age_days": 500})
    assert total == 40
    assert any(b["rule"] == "refund-velocity-over-3" for b in breakdown)


def test_vague_reason_scores():
    total, _ = score({"amount": 100, "reason": None, "customer_age_days": 500, "refund_velocity_24h": 0})
    assert total == 20


# ── tool_use ─────────────────────────────────────────────────────────

def test_tool_use_clean():
    total, _ = score({"tool": "email.send", "prompt": "hi", "max_tokens": 500}, action_type="tool_use")
    assert total == 0


def test_tool_use_privileged_namespace():
    total, breakdown = score({"tool": "system.exec", "prompt": "ls"}, action_type="tool_use")
    assert total == 40
    assert any(b["rule"] == "privileged-tool-namespace" for b in breakdown)


def test_tool_use_huge_prompt_triggers_review():
    total, _ = score({"tool": "llm.chat", "prompt": "x" * 60_000, "max_tokens": 500}, action_type="tool_use")
    assert total >= 30  # prompt-over-50k


def test_tool_use_missing_tool_name():
    total, breakdown = score({"prompt": "anything"}, action_type="tool_use")
    assert any(b["rule"] == "missing-tool-name" for b in breakdown)


# ── account_change ───────────────────────────────────────────────────

def test_account_change_multi_field_is_takeover():
    total, breakdown = score(
        {"new_email": "a@b.com", "new_phone": "+1234", "new_password": "xxx"},
        action_type="account_change",
    )
    assert total >= 40
    assert any(b["rule"] == "multi-identity-change" for b in breakdown)


def test_account_change_role_to_admin():
    total, _ = score({"new_role": "admin"}, action_type="account_change")
    assert total == 40


def test_account_change_fresh_account_email_review():
    total, _ = score(
        {"new_email": "x@y.com", "customer_age_days": 10},
        action_type="account_change",
    )
    # single field (15) + fresh account (20) = 35 (near review threshold)
    assert total == 35


# ── data_access ──────────────────────────────────────────────────────

def test_data_access_pii_column():
    total, breakdown = score(
        {"projection": "id, name, credit_card_number", "row_limit": 10, "tenant_id": "t1"},
        action_type="data_access",
    )
    assert total == 40
    assert any(b["rule"].startswith("pii-column") for b in breakdown)


def test_data_access_unbounded_scope():
    total, _ = score(
        {"operation": "read", "tenant_id": "t1", "row_limit": 0, "projection": "id"},
        action_type="data_access",
    )
    assert total == 30


def test_data_access_missing_tenant():
    total, breakdown = score(
        {"operation": "read", "row_limit": 10, "projection": "id"},
        action_type="data_access",
    )
    assert any(b["rule"] == "missing-tenant-scope" for b in breakdown)


# ── compliance ───────────────────────────────────────────────────────

def test_compliance_baseline_near_review():
    total, _ = score({"kind": "routine"}, action_type="compliance")
    # Baseline points (30) — below review threshold alone
    assert total == 30


def test_compliance_regulated_flow_triggers_review():
    total, _ = score({"kind": "aml_close"}, action_type="compliance")
    # baseline (30) + regulated-flow (30) = 60 → review
    assert total >= 50
    assert needs_review(total) is True


# ── unknown action_type ──────────────────────────────────────────────

def test_unknown_action_type_scores_zero():
    """Unknown action types get explicit zero instead of falling through to
    refund scorer (which would false-positive on domain-specific fields)."""
    total, breakdown = score({"amount": 999999}, action_type="telepathy")
    assert total == 0
    assert breakdown == []
