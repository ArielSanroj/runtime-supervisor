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
    SDK (`@runtime-supervisor/guards`) and arrow-function syntax — not Python.

    Uses an `agent-class` chokepoint (in an orchestrator file so it's tier 0 and
    survives the wrap-target filter) — `framework-import` chokepoints no longer
    reach `do_this_now` because they're treated as loop signals, not wrap points.
    """
    summary = RepoSummary(agent_chokepoints=[
        AgentChokepoint(file="packages/mcp/src/orchestrator.ts", line=230,
                        kind="agent-class", label="McpDispatcher"),
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


# 3. Framework-import handling — must NOT pollute "Best place to wrap first".
#
# A framework import (e.g. `from langchain.agents import initialize_agent`) is
# a loop *signal*, not a wrappable call-site. Including it under "Best place
# to wrap first" produced a self-contradicting bullet ("framework entrypoint —
# signals the loop, not the wrap point itself") — the section now lives in its
# own block ("Agent frameworks detected"), and `top_wrap_targets` only carries
# actually-wrappable chokepoints.

def test_framework_imports_excluded_from_wrap_targets():
    """Solo framework-import → wrap targets vacío, framework signals presentes."""
    cps = [AgentChokepoint(file="src/agents.py", line=5,
                           kind="framework-import", label="langchain")]
    summary = RepoSummary(agent_chokepoints=cps)
    sh = build_start_here(summary, [Finding(
        scanner="agent-orchestrators", file="src/agents.py", line=5,
        snippet="from langchain.agents import initialize_agent",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )])
    assert sh.top_wrap_targets == []
    assert len(sh.framework_signals) == 1
    assert sh.framework_signals[0].framework == "langchain"
    assert sh.framework_signals[0].file == "src/agents.py"
    assert sh.framework_signals[0].line == 5


def test_mixed_chokepoints_split_correctly():
    """agent-class + framework-import → wrap targets has only the class,
    framework signals has only the import."""
    cps = [
        AgentChokepoint(file="src/orchestrator.py", line=42,
                        kind="agent-class", label="Orch"),
        AgentChokepoint(file="src/imports.py", line=3,
                        kind="framework-import", label="langchain"),
    ]
    summary = RepoSummary(agent_chokepoints=cps)
    findings = [Finding(
        scanner="agent-orchestrators", file="src/imports.py", line=3,
        snippet="from langchain.agents import AgentExecutor",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )]
    sh = build_start_here(summary, findings)
    assert len(sh.top_wrap_targets) == 1
    assert sh.top_wrap_targets[0].label == "Orch"
    assert len(sh.framework_signals) == 1
    assert sh.framework_signals[0].framework == "langchain"


def test_framework_signals_section_rendered_in_md():
    """Markdown contains '## Agent frameworks detected' iff framework_signals
    is non-empty."""
    cps = [AgentChokepoint(file="src/x.py", line=1,
                           kind="framework-import", label="langchain")]
    summary = RepoSummary(agent_chokepoints=cps)
    findings = [Finding(
        scanner="agent-orchestrators", file="src/x.py", line=1,
        snippet="from langchain import …",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )]
    md_with = render_start_here_md(build_start_here(summary, findings))
    assert "## Agent frameworks detected" in md_with
    assert "**langchain**" in md_with

    md_without = render_start_here_md(build_start_here(RepoSummary(), []))
    assert "## Agent frameworks detected" not in md_without


def test_wrap_first_falls_back_with_framework_signals_no_contradiction():
    """When only framework imports exist, the 'Best place to wrap first' section
    must NOT carry the contradictory copy and must NAME the framework so the
    dev knows where the loop lives."""
    cps = [AgentChokepoint(file="repo/setup.py", line=11,
                           kind="framework-import", label="langchain")]
    summary = RepoSummary(agent_chokepoints=cps)
    findings = [Finding(
        scanner="agent-orchestrators", file="repo/setup.py", line=11,
        snippet="initialize_agent(tools, llm)",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )]
    md = render_start_here_md(build_start_here(summary, findings))

    # Slice the "Best place to wrap first" section out so we only assert on it.
    start = md.find("## Best place to wrap first")
    end = md.find("\n## ", start + 1)
    section = md[start:end]

    assert "signals the loop, not the wrap point itself" not in section, (
        "Regression: contradictory copy leaked back into 'Best place to wrap first'."
    )
    assert "langchain" in section
    assert "agent.run" in section or "AgentExecutor.invoke" in section


def test_no_wrap_no_signals_keeps_existing_empty_copy():
    """Empty summary keeps the original empty-state copy verbatim."""
    md = render_start_here_md(build_start_here(RepoSummary(), []))
    assert "No obvious wrap target" in md
    assert "## Agent frameworks detected" not in md


def test_render_md_section_order_with_frameworks():
    """When framework signals are present, the new section sits between
    'What this repo can already do' and 'Highest-risk things to care about now'."""
    cps = [AgentChokepoint(file="src/a.py", line=1,
                           kind="framework-import", label="langchain")]
    summary = RepoSummary(agent_chokepoints=cps)
    findings = [Finding(
        scanner="agent-orchestrators", file="src/a.py", line=1,
        snippet="from langchain import …",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )]
    md = render_start_here_md(build_start_here(summary, findings))
    expected_order = [
        "## Best place to wrap first",
        "## What this repo can already do",
        "## Agent frameworks detected",
        "## Highest-risk things to care about now",
        "## Do this now",
        "## Ignore this for now",
    ]
    last = -1
    for header in expected_order:
        idx = md.find(header)
        assert idx > last, f"section {header!r} missing or out of order"
        last = idx


def test_do_this_now_points_at_framework_when_no_wrap_targets():
    """When the only chokepoint is a framework-import, `do_this_now` must point
    at that framework + file:line and explicitly say 'not the import line'.

    Note the file is `repo/setup.py` — `setup.py` is a low-reachability path,
    but framework signals fall back to "show whatever we have" so the loop
    can still be communicated to the dev.
    """
    cps = [AgentChokepoint(file="repo/setup.py", line=11,
                           kind="framework-import", label="langchain")]
    summary = RepoSummary(agent_chokepoints=cps)
    findings = [Finding(
        scanner="agent-orchestrators", file="repo/setup.py", line=11,
        snippet="initialize_agent(tools, llm)",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"kind": "framework-import", "framework": "langchain"},
    )]
    sh = build_start_here(summary, findings)
    assert "langchain" in sh.do_this_now
    assert "setup.py:11" in sh.do_this_now
    assert "Tool(func" in sh.do_this_now or "agent.run" in sh.do_this_now


# 4. Reachability filter — low-reachability paths must not occupy the top
# of "Best place to wrap first" or "Highest-risk" sections.

def test_low_reachability_chokepoint_excluded_from_wrap_targets():
    """A chokepoint under `tests/`, `setup.py`, `scripts/`, `legacy/`, or
    `test-setup-*` must not be the FIRST place we point the dev at — the
    GiftedAgentV2 scenario where `langchain_NR_setup.py` headlined the wrap
    targets is the bug we're guarding against."""
    cps = [
        AgentChokepoint(file="src/agents/orchestrator.py", line=42,
                        kind="agent-class", label="ProdOrch"),
        AgentChokepoint(file="test-setup-newrelic/langchain_NR_setup.py",
                        line=11, kind="agent-class", label="TestOrch"),
    ]
    summary = RepoSummary(agent_chokepoints=cps)
    sh = build_start_here(summary, [])
    labels = [t.label for t in sh.top_wrap_targets]
    assert "ProdOrch" in labels
    assert "TestOrch" not in labels, (
        "test-setup-* path leaked into wrap targets — reachability filter broke."
    )


def test_low_reachability_finding_excluded_from_top_risks():
    """A `subprocess.run` in `setup.py` is real code but not the agent's
    runtime path. The supervincent scenario (build script flagged as
    'Shell execution present') is the regression to prevent."""
    findings = [Finding(
        scanner="fs-shell", file="setup.py", line=58,
        snippet="subprocess.check_call([sys.executable, '-m', 'pip', 'install'])",
        suggested_action_type="tool_use", confidence="high", rationale="...",
        extra={"family": "shell-exec"},
    )]
    sh = build_start_here(RepoSummary(), findings)
    families = [r.family for r in sh.top_risks]
    assert "fs-shell-shell-exec" not in families


def test_already_gated_finding_excluded_from_top_risks():
    """When gate_coverage marked a finding as `already_gated`, the START_HERE
    risks section must not tell the dev to 'do this now: wrap it'. Mirrors
    the supervincent post-onboarding scenario where the wrap was already
    applied but the report kept asking for it."""
    findings = [Finding(
        scanner="payment-calls", file="src/api/routes/payments.py", line=155,
        snippet="stripe.checkout.Session.create(",
        suggested_action_type="payment", confidence="high", rationale="...",
        extra={"already_gated": True, "gated_by": "guarded(...)"},
    )]
    sh = build_start_here(RepoSummary(), findings)
    assert sh.top_risks == []


# 5. Multi-method dispatcher — wrap copy must reflect that one decorator
# does NOT cover every public entry point.

def test_multi_method_dispatcher_changes_wrap_target_why():
    """When the chokepoint's class has ≥2 peer dispatch methods, the 'why'
    string explicitly says 'wrap each one' — the AlertDispatcher scenario
    where 5 dispatch_*_alert methods were collapsed into 'one wrapper covers
    all' (false claim)."""
    cp = AgentChokepoint(
        file="src/orchestrator.py", line=42,
        kind="agent-class", label="AlertDispatcher",
        parallel_methods=("dispatch_anomaly_alert", "dispatch_deadline_alert",
                          "dispatch_sla_alert"),
    )
    summary = RepoSummary(agent_chokepoints=[cp])
    sh = build_start_here(summary, [])
    assert len(sh.top_wrap_targets) == 1
    why = sh.top_wrap_targets[0].why
    assert "3 peer dispatch methods" in why
    assert "wrap each" in why
    assert "one wrapper" not in why  # the false claim must be gone


# 6. Step 0 — Bootstrap section
#
# Without this block, the very first paste of a wrap snippet fails with
# `ModuleNotFoundError: supervisor_guards`. Every test here guards against
# regressing to that state for at least one realistic repo shape.

def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_step_0_section_rendered_when_bootstrap_detected(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "fastapi\n")
    _write(tmp_path, "src/api/app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    sh = build_start_here(RepoSummary(), [], repo_root=tmp_path)
    md = render_start_here_md(sh)
    assert "## Step 0 — install the SDK" in md
    assert "pip install" in md
    assert "supervisor-guards" in md


def test_step_0_section_omitted_when_repo_root_not_passed():
    """Backwards compatibility: callers that don't provide `repo_root` get
    the previous output exactly — no Step 0 section."""
    sh = build_start_here(RepoSummary(), [])
    md = render_start_here_md(sh)
    assert "## Step 0" not in md
    assert sh.bootstrap is None


def test_step_0_section_omitted_when_no_manifest(tmp_path: Path):
    """Empty repo → BootstrapInfo with manager=None → renderer emits a
    softer block. Specifically must not crash and must mention how to
    proceed."""
    sh = build_start_here(RepoSummary(), [], repo_root=tmp_path)
    md = render_start_here_md(sh)
    assert "## Step 0 — install the SDK" in md
    # Generic copy when no manager is detected.
    assert "couldn't classify" in md.lower() or "your usual package manager" in md.lower()


def test_step_0_skips_configure_block_when_already_called(tmp_path: Path):
    """Mirrors supervincent — the entry point already calls
    `configure_supervisor()`. The Step 0 block must NOT show the wiring
    paste; instead it acknowledges the existing call."""
    _write(tmp_path, "requirements.txt", "fastapi\n")
    _write(tmp_path, "src/api/app.py", """
from fastapi import FastAPI
from supervisor_guards import configure_supervisor

configure_supervisor()
app = FastAPI()
""")
    sh = build_start_here(RepoSummary(), [], repo_root=tmp_path)
    md = render_start_here_md(sh)
    assert "already called near the FastAPI" in md
    # Must NOT emit the configure_supervisor() paste (with the import line).
    assert "from supervisor_guards import configure_supervisor" not in md


def test_step_0_picks_ts_when_top_wrap_target_is_typescript(tmp_path: Path):
    """Top wrap target is a `.ts` file → Step 0 block targets the JS manager,
    not Python, even when both are present in the repo."""
    _write(tmp_path, "backend/requirements.txt", "fastapi\n")
    _write(tmp_path, "frontend/package.json", '{"name":"web"}')
    _write(tmp_path, "frontend/pnpm-lock.yaml", "")
    cp = AgentChokepoint(
        file=str(tmp_path / "frontend/orchestrator.ts"),
        line=10, kind="agent-class", label="OrchestratorTS",
    )
    summary = RepoSummary(agent_chokepoints=[cp])
    sh = build_start_here(summary, [], repo_root=tmp_path)
    md = render_start_here_md(sh)
    assert "pnpm add @runtime-supervisor/guards" in md
    assert "pip install" not in md


def test_render_md_section_order_with_bootstrap(tmp_path: Path):
    """Step 0 must come BEFORE 'Best place to wrap first'."""
    _write(tmp_path, "requirements.txt", "fastapi\n")
    sh = build_start_here(RepoSummary(), [], repo_root=tmp_path)
    md = render_start_here_md(sh)
    expected_order = [
        "## Step 0 — install the SDK",
        "## Best place to wrap first",
        "## What this repo can already do",
        "## Highest-risk things to care about now",
        "## Do this now",
        "## Ignore this for now",
    ]
    last = -1
    for header in expected_order:
        idx = md.find(header)
        assert idx > last, f"section {header!r} missing or out of order"
        last = idx


def test_cli_render_includes_step_0_line(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "fastapi\n")
    sh = build_start_here(RepoSummary(), [], repo_root=tmp_path)
    lines = render_cli_start_here(sh, elapsed_s=1.0, root="x")
    joined = "\n".join(lines)
    assert "Step 0:" in joined
    # Must still fit inside the documented 5-20 line budget.
    assert 5 <= len(lines) <= 20


# 7. Decision-branching dispatcher picker
#
# When a class has methods named `handle()` / `execute()` (the names we'd
# preferred before) AND another method whose body actually branches on
# `if action == X` / `match action: case ...`, the AST-based picker should
# choose the branching method — that's the real dispatcher. The reviewer
# flagged on castor-1 that the snippet was pointing at a fictional `handle()`
# instead of the real `_execute_action(self, decision)`.

def test_dispatcher_method_with_decision_branching_beats_handle(tmp_path: Path):
    """Class has both `handle()` (no dispatch) and `_execute_action()` (real
    dispatch with `if action == ...`). Picker must prefer the branching one.
    Verified end-to-end via the rendered Python snippet."""
    _write(tmp_path, "src/agents/electoral.py", '''
from enum import Enum

class AgentAction(Enum):
    CREATE_INCIDENT = "create_incident"
    ESCALATE = "escalate"

class Decision:
    pass

class ElectoralIntelligenceAgent:
    def handle(self, payload):
        """Public entrypoint that just delegates."""
        return self._execute_action(payload)

    def _execute_action(self, decision: Decision):
        action = decision.action
        if action == AgentAction.CREATE_INCIDENT:
            return self._create()
        elif action == AgentAction.ESCALATE:
            return self._escalate()
        return None

    def _create(self): return 1
    def _escalate(self): return 2
''')
    cp = AgentChokepoint(
        file=str(tmp_path / "src/agents/electoral.py"),
        line=10, kind="agent-class", label="ElectoralIntelligenceAgent",
    )
    summary = RepoSummary(agent_chokepoints=[cp])
    sh = build_start_here(summary, [])
    # The "Do this now" snippet must point at the dispatcher method, not handle.
    assert "_execute_action" in sh.do_this_now
    assert "decision: Decision" in sh.do_this_now or "decision:" in sh.do_this_now
    # And it must NOT recommend the dummy handle() that just delegates.
    assert "def handle" not in sh.do_this_now


def test_match_statement_dispatcher_picked(tmp_path: Path):
    """Python 3.10+ structural match on a decision key — same signal as
    `if action == X` chains."""
    _write(tmp_path, "src/agents/router.py", '''
class RoutingAgent:
    def handle(self, payload):
        return None

    def route(self, intent):
        match intent:
            case "create": return 1
            case "delete": return 2
            case _: return None
''')
    cp = AgentChokepoint(
        file=str(tmp_path / "src/agents/router.py"),
        line=2, kind="agent-class", label="RoutingAgent",
    )
    summary = RepoSummary(agent_chokepoints=[cp])
    sh = build_start_here(summary, [])
    assert "def route" in sh.do_this_now
    assert "intent" in sh.do_this_now


def test_no_decision_branching_falls_back_to_name_preference(tmp_path: Path):
    """When no method has decision branching, the picker falls back to the
    existing name-based preference (handle wins over arbitrary names)."""
    _write(tmp_path, "src/agents/plain.py", '''
class PlainAgent:
    def utility(self): return 1
    def handle(self, payload): return self.utility()
    def helper(self): return 2
''')
    cp = AgentChokepoint(
        file=str(tmp_path / "src/agents/plain.py"),
        line=2, kind="agent-class", label="PlainAgent",
    )
    summary = RepoSummary(agent_chokepoints=[cp])
    sh = build_start_here(summary, [])
    assert "def handle" in sh.do_this_now
