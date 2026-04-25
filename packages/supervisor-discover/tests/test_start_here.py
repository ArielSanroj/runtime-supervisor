"""Tests for the StartHere data structure + renderers.

Validates the four-question contract from docs/SCAN_COMMUNICATION_RULES.md:
  1. Where do I add the first wrapper?  (top_wrap_targets)
  2. What can this repo do?              (repo_capabilities)
  3. Highest-risk things to watch?       (top_risks)
  4. What to ignore?                     (hidden_counter)

Plus the rendering contracts (markdown sections, CLI line count, plain language).
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.findings import Finding
from supervisor_discover.scanners import apply_default_hidden, scan_all
from supervisor_discover.start_here import (
    Risk,
    StartHere,
    WrapTarget,
    build_start_here,
    render_cli_start_here,
    render_start_here_md,
)
from supervisor_discover.summary import AgentChokepoint, RepoSummary, build_summary

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def _build_for_fixture(fixture: Path) -> tuple[RepoSummary, list[Finding], StartHere]:
    all_findings = validate(scan_all(fixture))
    visible, hidden = apply_default_hidden(all_findings, fixture)
    summary = build_summary(visible, hidden_counts=hidden)
    sh = build_start_here(summary, visible)
    return summary, visible, sh


# 1. Selection rules

def test_top_wrap_targets_capped_at_three():
    cps = [
        AgentChokepoint(file=f"a{i}.py", line=10 + i, kind="agent-class", label=f"Cls{i}")
        for i in range(7)
    ]
    summary = RepoSummary(agent_chokepoints=cps)
    sh = build_start_here(summary, [])
    assert len(sh.top_wrap_targets) == 3


def test_top_wrap_targets_uses_chokepoint_rank_priority():
    """A factory-file agent-class (tier 0) must sort before a non-factory one (tier 2)."""
    cps = [
        AgentChokepoint(file="src/random.py",       line=99, kind="agent-class", label="OtherCls"),
        AgentChokepoint(file="src/orchestrator.py", line=15, kind="agent-class", label="Orch"),
    ]
    summary = RepoSummary(agent_chokepoints=cps)
    sh = build_start_here(summary, [])
    assert sh.top_wrap_targets[0].label == "Orch"


def test_capabilities_use_plain_english_phrases():
    _summary, _findings, sh = _build_for_fixture(FLASK_FIXTURE)
    # Flask fixture has stripe + LLM SDKs — should produce these plain phrases.
    assert "move money" in sh.repo_capabilities
    # Phrasing should be plain — no jargon words in capability strings.
    for cap in sh.repo_capabilities:
        for forbidden in ("OWASP", "CVSS", "RCE", "exfiltration"):
            assert forbidden not in cap, f"jargon {forbidden!r} leaked into capability {cap!r}"


def test_top_risks_only_when_capability_confirmed_high():
    """A finding with confidence='medium' must NOT generate a Risk card."""
    f = Finding(
        scanner="fs-shell", file="x.py", line=1, snippet="subprocess.run(",
        suggested_action_type="tool_use", confidence="medium", rationale="...",
        extra={"family": "shell-exec"},
    )
    summary = RepoSummary()
    sh = build_start_here(summary, [f])
    assert len(sh.top_risks) == 0


def test_top_risks_ordered_by_severity_payment_before_llm():
    """payment-calls (severity 100) must precede llm-calls (severity 30)."""
    payment = Finding(
        scanner="payment-calls", file="p.py", line=10, snippet="stripe.Charge.create(",
        suggested_action_type="payment", confidence="high", rationale="...", extra={},
    )
    llm = Finding(
        scanner="llm-calls", file="l.py", line=20, snippet="openai.ChatCompletion.create(",
        suggested_action_type="tool_use", confidence="high", rationale="...", extra={},
    )
    sh = build_start_here(RepoSummary(), [llm, payment])  # input order LLM first
    assert sh.top_risks[0].family == "payment-calls"
    assert sh.top_risks[1].family == "llm-calls"


def test_top_risks_capped_at_three():
    findings = [
        Finding(scanner=s, file=f"{s}.py", line=1, snippet=f"{s}_call(",
                suggested_action_type="tool_use", confidence="high", rationale="...",
                extra={"family": "shell-exec"} if s == "fs-shell" else {})
        for s in ("payment-calls", "fs-shell", "email-sends", "messaging", "llm-calls")
    ]
    sh = build_start_here(RepoSummary(), findings)
    assert len(sh.top_risks) == 3


def test_do_this_now_includes_supervised_snippet():
    summary = RepoSummary(agent_chokepoints=[
        AgentChokepoint(file="src/orchestrator.py", line=42, kind="agent-class", label="Orch"),
    ])
    sh = build_start_here(summary, [])
    assert "@supervised" in sh.do_this_now
    assert "supervisor_guards" in sh.do_this_now
    # Python file → Python fence + decorator syntax (no TS-only `import { ... }`).
    assert "```python" in sh.do_this_now
    assert "import {" not in sh.do_this_now


def test_do_this_now_uses_typescript_snippet_for_ts_file():
    """When the wrap target lives in a .ts file, the snippet must use the TS
    SDK (`@runtime-supervisor/guards`) and arrow-function syntax — not Python."""
    summary = RepoSummary(agent_chokepoints=[
        AgentChokepoint(file="packages/mcp/src/index.ts", line=230, kind="framework-import", label="mcp-dispatcher"),
    ])
    sh = build_start_here(summary, [])
    assert "```ts" in sh.do_this_now
    assert "@runtime-supervisor/guards" in sh.do_this_now
    # Must NOT leak Python idioms into a TS snippet.
    assert "supervisor_guards" not in sh.do_this_now
    assert "@supervised(" in sh.do_this_now or "supervised(" in sh.do_this_now


def test_hidden_counter_carries_through_from_summary():
    summary = RepoSummary(hidden_findings={"tests": 12, "legacy": 4})
    sh = build_start_here(summary, [])
    assert sh.hidden_counter == {"tests": 12, "legacy": 4}


# 2. Rendering contracts

def test_render_start_here_md_has_required_sections():
    _summary, _findings, sh = _build_for_fixture(FLASK_FIXTURE)
    md = render_start_here_md(sh)
    # Spec mandates these section headers, in this order.
    expected = [
        "## Best place to wrap first",
        "## What this repo can already do",
        "## Highest-risk things to care about now",
        "## Do this now",
        "## Ignore this for now",
    ]
    last = -1
    for header in expected:
        idx = md.find(header)
        assert idx > last, f"section {header!r} missing or out of order"
        last = idx


def test_render_cli_start_here_under_20_lines():
    _summary, _findings, sh = _build_for_fixture(FLASK_FIXTURE)
    lines = render_cli_start_here(sh, elapsed_s=1.2, root="fake_flask_app")
    assert 5 <= len(lines) <= 20, f"expected 5-20 CLI lines, got {len(lines)}"


def test_empty_findings_shows_no_obvious_wrap_target():
    sh = build_start_here(RepoSummary(), [])
    md = render_start_here_md(sh)
    assert "No obvious wrap target" in md
    # Capabilities section also shows the empty-state copy.
    assert "No high-stakes capabilities" in md


def test_render_md_includes_hidden_counter_when_present():
    sh = StartHere(hidden_counter={"tests": 7, "legacy": 3})
    md = render_start_here_md(sh)
    assert "10 findings hidden" in md
    assert "7 tests" in md and "3 legacy" in md
