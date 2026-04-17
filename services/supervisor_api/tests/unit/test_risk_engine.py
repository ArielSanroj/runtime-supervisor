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
