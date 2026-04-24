"""build_summary aggregates signals across scanners deterministically."""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.scanners import scan_all
from supervisor_discover.summary import build_summary, render_cli_stdout, render_markdown

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def test_summary_detects_flask_stripe_llms_on_flask_fixture():
    findings = validate(scan_all(FLASK_FIXTURE))
    s = build_summary(findings)
    assert "flask" in [fw.lower() for fw in s.frameworks]
    assert "stripe" in s.payment_integrations
    # fixture has anthropic + openai imports
    assert "Anthropic Claude" in s.llm_providers
    assert "OpenAI" in s.llm_providers
    assert s.total_findings > 0


def test_summary_omits_unknown_framework():
    findings = validate(scan_all(FLASK_FIXTURE))
    s = build_summary(findings)
    # "unknown" is emitted by the http-routes scanner when it can't classify;
    # summary filters it out.
    assert "unknown" not in [fw.lower() for fw in s.frameworks]


def test_summary_markdown_has_required_sections():
    findings = validate(scan_all(FLASK_FIXTURE))
    s = build_summary(findings)
    md = render_markdown(s)
    assert "## What this repo is" in md
    assert "Stack:" in md
    assert "In one line:" in md


def test_summary_cli_stdout_is_three_lines():
    findings = validate(scan_all(FLASK_FIXTURE))
    s = build_summary(findings)
    lines = render_cli_stdout(s)
    assert len(lines) == 3
    assert all("  " in ln for ln in lines)  # indented


def test_summary_on_empty_findings():
    s = build_summary([])
    md = render_markdown(s)
    assert "no critical integrations" in s.one_liner.lower() or s.one_liner != ""
    assert "## What this repo is" in md
