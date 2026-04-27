"""Reachability refinement of LLM-paired combos.

Background: LLM+shell-exec / LLM+fs-delete / LLM+fs-write / LLM+payment /
LLM+account-change used to fire on pure co-occurrence — same repo was
enough. On framework repos like langchain the LLM module and the
side-effect module live in different sub-packages with no import path
between them; the "LLM-to-RCE pipeline" narrative was structurally
wrong.

When `detect_combos(findings, root=...)` gets a repo root, it now
post-processes those combos against the within-repo import graph:
- No path either direction → severity drops to `low`, narrative
  appends "no import path was found".
- Path exists → narrative appends the resolved chain as evidence.

These tests cover both branches end-to-end against real on-disk source.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.combos import detect_combos
from supervisor_discover.findings import Finding


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


def _llm_finding(file: str) -> Finding:
    return Finding(
        scanner="llm-calls", file=file, line=1, snippet="openai.create",
        suggested_action_type="tool_use", confidence="high",
        rationale="...", extra={"kind": "invocation"},
    )


def _shell_finding(file: str) -> Finding:
    return Finding(
        scanner="fs-shell", file=file, line=1, snippet="subprocess.Popen",
        suggested_action_type="tool_use", confidence="high",
        rationale="...", extra={"family": "shell-exec"},
    )


def _fs_delete_finding(file: str) -> Finding:
    return Finding(
        scanner="fs-shell", file=file, line=1, snippet="shutil.rmtree",
        suggested_action_type="tool_use", confidence="high",
        rationale="...", extra={"family": "fs-delete"},
    )


# ─── Disconnected modules: severity downgrades ────────────────────


def test_unreachable_llm_plus_shell_exec_downgraded(tmp_path: Path):
    """The langchain shape: chains/ has the LLM, agents/middleware/ has
    the subprocess, neither imports the other. Severity must drop to
    `low` and narrative must say so explicitly."""
    llm = _write(tmp_path, "chains/moderation.py", "import openai\n")
    sh = _write(tmp_path, "agents/middleware/_execution.py", "import subprocess\n")
    findings = [_llm_finding(str(llm)), _shell_finding(str(sh))]
    combos = detect_combos(findings, root=tmp_path)
    combo = next(c for c in combos if c.id == "llm-plus-shell-exec")
    assert combo.severity == "low"
    assert "No import path" in combo.narrative


def test_unreachable_llm_plus_fs_delete_downgraded(tmp_path: Path):
    llm = _write(tmp_path, "chains/llm.py", "import openai\n")
    rm = _write(tmp_path, "tools/cleanup.py", "import shutil\n")
    findings = [_llm_finding(str(llm)), _fs_delete_finding(str(rm))]
    combos = detect_combos(findings, root=tmp_path)
    combo = next(c for c in combos if c.id == "llm-plus-fs-delete")
    assert combo.severity == "low"


def test_unreachable_llm_plus_payment_downgraded(tmp_path: Path):
    llm = _write(tmp_path, "chains/llm.py", "import openai\n")
    pay = _write(tmp_path, "billing/refund.py", "import stripe\n")
    findings = [
        _llm_finding(str(llm)),
        Finding(
            scanner="payment-calls", file=str(pay), line=1, snippet="stripe.Refund",
            suggested_action_type="payment", confidence="high",
            rationale="...", extra={"vendor": "stripe"},
        ),
    ]
    combos = detect_combos(findings, root=tmp_path)
    combo = next(c for c in combos if c.id == "llm-plus-payment")
    assert combo.severity == "low"


# ─── Connected modules: stay critical, narrative gains the path ───


def test_reachable_llm_plus_shell_exec_keeps_severity(tmp_path: Path):
    """`llm.py` imports `shell.py` directly → reachability fires.
    Severity stays `critical`; narrative appends the import path."""
    llm = _write(tmp_path, "llm.py", "import shell\nimport openai\n")
    sh = _write(tmp_path, "shell.py", "import subprocess\n")
    findings = [_llm_finding(str(llm)), _shell_finding(str(sh))]
    combos = detect_combos(findings, root=tmp_path)
    combo = next(c for c in combos if c.id == "llm-plus-shell-exec")
    assert combo.severity == "critical"
    assert "Import path detected" in combo.narrative
    assert "shell.py" in combo.narrative
    # Evidence list gets the rendered chain appended for auditability.
    assert any("reach:" in e for e in combo.evidence)


def test_reachable_via_intermediate_module(tmp_path: Path):
    """Two-hop reachability: `agent.py → util.py → shell.py` (where
    `util.py` is the bridge). The combo should still fire and the
    rendered path should include all three nodes."""
    llm = _write(tmp_path, "agent.py", "import util\nimport openai\n")
    _write(tmp_path, "util.py", "import shell\n")
    sh = _write(tmp_path, "shell.py", "import subprocess\n")
    findings = [_llm_finding(str(llm)), _shell_finding(str(sh))]
    combos = detect_combos(findings, root=tmp_path)
    combo = next(c for c in combos if c.id == "llm-plus-shell-exec")
    assert combo.severity == "critical"
    assert "agent.py" in combo.narrative
    assert "util.py" in combo.narrative
    assert "shell.py" in combo.narrative


# ─── No-root mode: behaviour unchanged from before ────────────────


def test_no_root_keeps_legacy_severity(tmp_path: Path):
    """When no `root` is passed, the refinement step is skipped and the
    rule's hardcoded severity stays — keeps backward compatibility for
    callers that still rehydrate from persisted findings."""
    llm = _write(tmp_path, "chains/llm.py", "import openai\n")
    sh = _write(tmp_path, "agents/middleware/_execution.py", "import subprocess\n")
    findings = [_llm_finding(str(llm)), _shell_finding(str(sh))]
    combos = detect_combos(findings)  # no root
    combo = next(c for c in combos if c.id == "llm-plus-shell-exec")
    # Default severity from the rule; should NOT have been demoted.
    assert combo.severity == "critical"
    assert "No import path" not in combo.narrative


# ─── Combos that aren't in the LLM-paired list don't get touched ──


def test_unrelated_combo_not_refined(tmp_path: Path):
    """`agent-orchestrator-present` is not a directional flow combo and
    has no entry in `_LLM_PAIRED_COMBOS`. Reachability refinement must
    leave it alone — its severity comes from the rule logic."""
    findings = [
        Finding(
            scanner="agent-orchestrators", file=str(tmp_path / "agent.py"),
            line=1, snippet="class Dispatcher", suggested_action_type="tool_use",
            confidence="high", rationale="...",
            extra={"kind": "agent-class", "class_name": "Dispatcher"},
        ),
        Finding(
            scanner="agent-orchestrators", file=str(tmp_path / "tools.py"),
            line=1, snippet="dispatcher.register('refund'", suggested_action_type="tool_use",
            confidence="high", rationale="...",
            extra={"kind": "tool-registration", "tool_name": "refund"},
        ),
    ]
    combos = detect_combos(findings, root=tmp_path)
    orch = next(c for c in combos if c.id == "agent-orchestrator")
    # `_agent_orchestrator_present` returns critical when both classes
    # AND registrations are present — must survive the refinement pass.
    assert orch.severity == "critical"
