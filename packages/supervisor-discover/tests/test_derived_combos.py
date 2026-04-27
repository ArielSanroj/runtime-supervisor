"""Tests for the LLM × {payment, account-change} combo detectors.

The reviewer flagged these on supervincent — Anthropic + Stripe + DB
writes on user tables coexist, but no combo fired to push the dev to
the right policy. Now `llm-plus-payment` (critical) and
`llm-plus-account-change` (high) fill that gap.
"""
from __future__ import annotations

from supervisor_discover.combos import detect_combos
from supervisor_discover.findings import Finding


def _f(scanner: str, file: str = "/r/x.py", line: int = 1,
       confidence: str = "high",
       extra: dict | None = None) -> Finding:
    return Finding(
        scanner=scanner, file=file, line=line, snippet="x",
        suggested_action_type="tool_use", confidence=confidence,
        rationale="...", extra=extra or {},
    )


def _ids(combos):
    return [c.id for c in combos]


# ─── llm + payment ─────────────────────────────────────────────────


def test_llm_plus_payment_fires_with_both():
    findings = [
        _f("llm-calls", file="/r/llm.py"),
        _f("payment-calls", file="/r/billing.py", extra={"vendor": "stripe"}),
    ]
    combos = detect_combos(findings)
    assert "llm-plus-payment" in _ids(combos)
    payment_combo = next(c for c in combos if c.id == "llm-plus-payment")
    assert payment_combo.severity == "critical"


def test_llm_plus_payment_does_not_fire_without_payment():
    findings = [_f("llm-calls", file="/r/llm.py")]
    assert "llm-plus-payment" not in _ids(detect_combos(findings))


def test_llm_plus_payment_does_not_fire_without_llm():
    findings = [
        _f("payment-calls", file="/r/billing.py", extra={"vendor": "stripe"}),
    ]
    assert "llm-plus-payment" not in _ids(detect_combos(findings))


# ─── llm + account change ──────────────────────────────────────────


def test_llm_plus_account_change_fires_on_user_table_writes():
    findings = [
        _f("llm-calls", file="/r/llm.py"),
        _f("db-mutations", file="/r/users_repo.py",
           extra={"verb": "UPDATE", "table": "users"}),
    ]
    combos = detect_combos(findings)
    assert "llm-plus-account-change" in _ids(combos)
    combo = next(c for c in combos if c.id == "llm-plus-account-change")
    assert combo.severity == "high"


def test_llm_plus_account_change_fires_on_customer_table_writes():
    findings = [
        _f("llm-calls", file="/r/llm.py"),
        _f("db-mutations", file="/r/x.py",
           extra={"verb": "INSERT", "table": "customers"}),
    ]
    assert "llm-plus-account-change" in _ids(detect_combos(findings))


def test_llm_plus_account_change_does_not_fire_on_unrelated_tables():
    """Writes on `logs` / `events` aren't account-change risks — the combo
    should only fire when the table is in the sensitive set."""
    findings = [
        _f("llm-calls", file="/r/llm.py"),
        _f("db-mutations", file="/r/x.py",
           extra={"verb": "INSERT", "table": "logs"}),
    ]
    assert "llm-plus-account-change" not in _ids(detect_combos(findings))


def test_llm_plus_account_change_does_not_fire_without_llm():
    findings = [
        _f("db-mutations", file="/r/users.py",
           extra={"verb": "UPDATE", "table": "users"}),
    ]
    assert "llm-plus-account-change" not in _ids(detect_combos(findings))


# ─── Both fire together (the supervincent shape) ──────────────────


def test_both_combos_fire_together():
    """Repo has LLM + payment + user-table writes — both new combos
    should trigger alongside the existing llm-plus-shell-exec etc."""
    findings = [
        _f("llm-calls", file="/r/llm.py"),
        _f("payment-calls", file="/r/billing.py", extra={"vendor": "stripe"}),
        _f("db-mutations", file="/r/users_repo.py",
           extra={"verb": "UPDATE", "table": "users"}),
    ]
    ids = _ids(detect_combos(findings))
    assert "llm-plus-payment" in ids
    assert "llm-plus-account-change" in ids
