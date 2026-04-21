"""narrator.render_summary produces the mandable SUMMARY.md.

Critical behaviours:
- test-path findings go to 🗑️ discard, not 🔒
- setup/install-path findings go to ⚠️ confirm, not 🔒
- high-confidence prod findings go to 🔒
- agent-class findings go to 🎯 wrap (and lead the list)
- "No me preocupa" appears when money/customer tiers are clean
- Combos section appears when combos passed in
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.combos import detect_combos
from supervisor_discover.findings import Finding
from supervisor_discover.narrator import (
    _bucket_findings,
    _classify_path,
    render_summary,
)
from supervisor_discover.scanners import scan_all
from supervisor_discover.summary import build_summary

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def _f(file: str, scanner: str = "fs-shell", confidence: str = "high", **extra) -> Finding:
    return Finding(
        scanner=scanner,
        file=file,
        line=1,
        snippet="x",
        suggested_action_type="tool_use",
        confidence=confidence,
        rationale="test",
        extra=extra,
    )


def test_classify_path_separates_test_install_prod():
    assert _classify_path("/repo/tests/test_foo.py") == "test"
    assert _classify_path("/repo/__tests__/bar.ts") == "test"
    assert _classify_path("/repo/setup.py") == "install"
    assert _classify_path("/repo/scripts/install.sh") == "install"
    assert _classify_path("/repo/app.py") == "prod"
    assert _classify_path("/repo/src/api/handler.py") == "prod"


def test_bucket_sends_tests_to_discard():
    findings = [_f("/repo/tests/test_api.py", confidence="high")]
    buckets = _bucket_findings(findings)
    assert len(buckets["discard"]) == 1
    assert buckets["prod"] == []


def test_bucket_sends_setup_scripts_to_confirm():
    findings = [_f("/repo/setup.py", confidence="high")]
    buckets = _bucket_findings(findings)
    assert len(buckets["confirm"]) == 1
    assert buckets["prod"] == []


def test_bucket_sends_high_prod_to_prod():
    findings = [_f("/repo/handler.py", confidence="high")]
    buckets = _bucket_findings(findings)
    assert len(buckets["prod"]) == 1


def test_bucket_sends_medium_prod_to_confirm():
    findings = [_f("/repo/handler.py", confidence="medium")]
    buckets = _bucket_findings(findings)
    assert len(buckets["confirm"]) == 1
    assert buckets["prod"] == []


def test_bucket_sends_agent_class_to_wrap():
    findings = [_f(
        "/repo/core/crew_factory.py",
        scanner="agent-orchestrators",
        confidence="high",
        kind="agent-class",
        class_name="CrewFactory",
    )]
    buckets = _bucket_findings(findings)
    assert len(buckets["wrap"]) == 1
    assert buckets["prod"] == []


def test_bucket_skips_framework_imports_from_priority():
    """Framework imports are surfaced as narrative text, not as a priority
    bullet — they're signal, not an action."""
    findings = [_f(
        "/repo/agents/researcher.py",
        scanner="agent-orchestrators",
        confidence="high",
        kind="framework-import",
        framework="crewai",
    )]
    buckets = _bucket_findings(findings)
    assert buckets["wrap"] == []
    assert buckets["prod"] == []
    assert buckets["confirm"] == []
    assert buckets["discard"] == []


def test_render_summary_emits_priority_emojis():
    findings = [
        _f("/repo/handler.py", scanner="email-sends", confidence="high"),
        _f("/repo/setup.py", scanner="fs-shell", confidence="high"),
        _f("/repo/tests/test_api.py", scanner="fs-shell", confidence="high"),
    ]
    summary = build_summary(findings)
    md = render_summary(summary, findings)
    assert "🔒" in md  # prod
    assert "⚠️" in md  # confirm (setup.py)
    assert "🗑️" in md  # discard (test)


def test_render_summary_empty_repo_says_nothing_to_do():
    summary = build_summary([])
    md = render_summary(summary, [])
    assert "no encontré" in md.lower() or "nada" in md.lower()


def test_render_summary_flask_fixture_integration():
    """End-to-end on a real fixture — the generated markdown should reference
    the fixture's actual capabilities."""
    findings = validate(scan_all(FLASK_FIXTURE))
    summary = build_summary(findings)
    combos = detect_combos(findings)
    md = render_summary(summary, findings, combos, repo_name="fake_flask_app")

    assert "fake_flask_app" in md  # repo name in title
    assert "security review" in md.lower()
    assert "Timeline sugerido" in md
    # fixture has Stripe → "no me preocupa" should NOT say "sin SDKs de pago"
    assert "Sin SDKs de pago" not in md


def test_render_summary_clean_tiers_note_when_no_money_no_pii():
    """A repo with only fs-shell findings should say 'no money, no customer
    data' so the reader knows those tiers were actually checked."""
    findings = [_f("/repo/handler.py", scanner="fs-shell", confidence="high")]
    summary = build_summary(findings)
    md = render_summary(summary, findings)
    assert "Sin SDKs de pago" in md
    assert "Sin mutaciones directas" in md


def test_render_summary_includes_combos_section_when_passed():
    findings = [_f(
        "/repo/core/crew_factory.py",
        scanner="agent-orchestrators",
        confidence="high",
        kind="agent-class",
        class_name="CrewFactory",
    )]
    summary = build_summary(findings)
    combos = detect_combos(findings)
    md = render_summary(summary, findings, combos)
    assert "Combos detectados" in md
    assert "runtime-supervisor/combos/" in md


def test_render_summary_wrap_item_leads_priority_list():
    """Wrap items (agent chokepoints) should come before 🔒 prod items."""
    findings = [
        _f("/repo/handler.py", scanner="email-sends", confidence="high"),
        _f(
            "/repo/core/crew.py",
            scanner="agent-orchestrators",
            confidence="high",
            kind="agent-class",
            class_name="CrewRunner",
        ),
    ]
    summary = build_summary(findings)
    md = render_summary(summary, findings)
    wrap_pos = md.find("🎯")
    prod_pos = md.find("🔒")
    assert wrap_pos != -1, "🎯 wrap emoji missing"
    assert prod_pos != -1, "🔒 prod emoji missing"
    assert wrap_pos < prod_pos, "wrap items should come before prod items"
