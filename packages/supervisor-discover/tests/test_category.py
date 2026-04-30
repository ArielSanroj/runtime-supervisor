"""Category taxonomy — every finding maps to a (primary, secondary…) pair.

The category axis is orthogonal to the tier axis: a tier says *which
surface* (money / customer-data / real-world / business / llm / general),
a category says *which dimension of pain* (security / efficiency /
quality). The primary drives sort order and chip color in the UI; the
secondary list surfaces real-but-not-headline aspects.
"""
from __future__ import annotations

from supervisor_discover.classifier import (
    CategoryLabels,
    categorize,
    group_by_category,
)
from supervisor_discover.findings import Finding


def _f(scanner: str, *, confidence: str = "high", **extra) -> Finding:
    return Finding(
        scanner=scanner,
        file="/repo/x.ts",
        line=1,
        snippet="",
        suggested_action_type="tool_use",
        confidence=confidence,  # type: ignore[arg-type]
        rationale="",
        extra=extra,
    )


def test_payment_calls_are_security_primary_efficiency_secondary():
    assert categorize(_f("payment-calls")) == CategoryLabels("security", ("efficiency",))


def test_voice_actions_are_security_primary_efficiency_secondary():
    assert categorize(_f("voice-actions")) == CategoryLabels("security", ("efficiency",))


def test_messaging_email_calendar_are_security_primary_quality_secondary():
    for scanner in ("messaging", "email-sends", "calendar-actions"):
        assert categorize(_f(scanner)).primary == "security"
        assert "quality" in categorize(_f(scanner)).secondary


def test_agent_orchestrator_carries_all_three_axes():
    labels = categorize(_f("agent-orchestrators"))
    assert labels.primary == "security"
    assert set(labels.secondary) == {"efficiency", "quality"}


def test_fs_shell_exec_and_delete_are_security():
    for fam in ("shell-exec", "fs-delete"):
        assert categorize(_f("fs-shell", family=fam)).primary == "security"


def test_fs_shell_write_is_quality_primary_security_secondary():
    labels = categorize(_f("fs-shell", family="fs-write"))
    assert labels.primary == "quality"
    assert "security" in labels.secondary


def test_db_mutation_on_customer_table_is_security():
    f = _f("db-mutations", table="users")
    assert categorize(f).primary == "security"


def test_db_mutation_on_business_table_is_quality():
    # `agent_events`, `trades`, `inventory`, etc. fall through to business_data
    f = _f("db-mutations", table="agent_events")
    labels = categorize(f)
    assert labels.primary == "quality"
    assert set(labels.secondary) == {"security", "efficiency"}


def test_llm_calls_high_confidence_is_efficiency():
    # A real .create() invocation — token burn dominates user pain
    f = _f("llm-calls", confidence="high")
    labels = categorize(f)
    assert labels.primary == "efficiency"
    assert set(labels.secondary) == {"security", "quality"}


def test_llm_calls_low_confidence_constructor_is_quality():
    # Just `new OpenAI()` — no prompt has fired yet, gate the .create() instead
    f = _f("llm-calls", confidence="low")
    assert categorize(f).primary == "quality"


def test_http_routes_and_skills_are_quality_only_no_secondaries():
    # Surface-map / content-review findings have no second axis worth flagging
    for scanner in ("http-routes", "skills"):
        labels = categorize(_f(scanner))
        assert labels.primary == "quality"
        assert labels.secondary == ()


def test_cron_schedules_is_quality_primary_security_secondary():
    # The headline is "this runs every hour"; injection is the secondary
    labels = categorize(_f("cron-schedules"))
    assert labels.primary == "quality"
    assert "security" in labels.secondary


def test_unknown_scanner_falls_back_to_quality_no_secondary():
    labels = categorize(_f("brand-new-scanner"))
    assert labels == CategoryLabels("quality", ())


def test_primary_is_never_in_its_own_secondary_list():
    # Invariant: secondary excludes the primary, no duplicates
    for scanner in (
        "payment-calls", "voice-actions", "messaging", "email-sends",
        "calendar-actions", "media-gen", "agent-orchestrators", "mcp-tools",
        "cron-schedules", "http-routes", "skills",
    ):
        labels = categorize(_f(scanner))
        assert labels.primary not in labels.secondary
        assert len(set(labels.secondary)) == len(labels.secondary)


def test_group_by_category_buckets_match_categorize():
    findings = [
        _f("payment-calls"),                            # security
        _f("voice-actions"),                            # security
        _f("llm-calls", confidence="high"),             # efficiency
        _f("db-mutations", table="agent_events"),       # quality
        _f("http-routes"),                              # quality
    ]
    buckets = group_by_category(findings)
    assert len(buckets["security"]) == 2
    assert len(buckets["efficiency"]) == 1
    assert len(buckets["quality"]) == 2
