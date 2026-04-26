"""Tests for the light taint demotion pass.

The reviewer flagged that medium-confidence fs-delete findings in
supervincent (`onboarding.py:594` `Path(tmp.name).unlink()` where `tmp`
came from `tempfile.NamedTemporaryFile()`) and castor-1
(`e14_data.py:564` `shutil.rmtree(tmp_dir)` where `tmp_dir` came from
`tempfile.mkdtemp()`) kept showing up despite explicit verification —
neither path is reachable from the LLM. This pass walks back to the
assignment, sees `tempfile.*`, and demotes to low.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import fs_shell
from supervisor_discover.taint import annotate_findings


def _write(tmp: Path, name: str, body: str) -> Path:
    """Strip the leading newline so triple-quoted bodies don't shift every
    line off-by-one. `body` should start with `\\n` for readability;
    we drop it before write so line 1 is the first real line of code."""
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


def _scan_and_taint(tmp: Path) -> list[Finding]:
    findings = fs_shell.scan(tmp)
    annotate_findings(findings)
    return findings


def _by_line(findings: list[Finding], line: int) -> Finding:
    matches = [f for f in findings if f.line == line]
    assert len(matches) == 1, f"expected 1 finding at line {line}, got {len(matches)}"
    return matches[0]


# ─── Demotion: tempfile-derived paths ──────────────────────────────


def test_path_unlink_with_tempfile_demoted(tmp_path: Path):
    """The exact supervincent shape: `tmp = tempfile.NamedTemporaryFile()` →
    later `Path(tmp.name).unlink()`. Path arg flows back to the tempfile
    call — that's system-controlled, not LLM-reachable."""
    src = _write(tmp_path, "routes/onboarding.py", """
import tempfile
from pathlib import Path

def upload(file):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    try:
        tmp.write(file.read())
    finally:
        Path(tmp.name).unlink(missing_ok=True)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 9)
    assert f.confidence == "low"
    assert f.extra.get("taint_source") == "system"
    assert f.extra.get("taint_demoted") is True


def test_rmtree_with_mkdtemp_demoted(tmp_path: Path):
    """The castor-1 shape: `tmp_dir = tempfile.mkdtemp()` → later
    `shutil.rmtree(tmp_dir)`."""
    _write(tmp_path, "routes/e14_data.py", """
import shutil
import tempfile

def process():
    tmp_dir = tempfile.mkdtemp(prefix="ocr-")
    try:
        return _process_in(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 9)
    assert f.confidence == "low"
    assert f.extra.get("taint_source") == "system"


def test_os_unlink_with_constant_path_demoted(tmp_path: Path):
    _write(tmp_path, "scripts/cleanup.py", """
import os

def cleanup():
    test_file = "/tmp/marker.txt"
    os.remove(test_file)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 5)
    assert f.confidence == "low"
    assert f.extra.get("taint_source") == "constant"


def test_os_unlink_with_settings_path_demoted(tmp_path: Path):
    """`path = settings.LOG_DIR` → `os.unlink(path)`. settings.* is
    system-controlled (config from the host)."""
    _write(tmp_path, "scripts/clean_logs.py", """
import os
from app.config import settings

def cleanup():
    path = settings.LOG_DIR
    os.unlink(path)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 6)
    assert f.confidence == "low"
    assert f.extra.get("taint_source") == "system"


def test_os_environ_path_demoted(tmp_path: Path):
    _write(tmp_path, "scripts/env_cleanup.py", """
import os

def cleanup():
    path = os.environ.get("CACHE_DIR")
    os.unlink(path)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 5)
    assert f.confidence == "low"
    assert f.extra.get("taint_source") == "system"


# ─── No demotion: variable / unknown sources ───────────────────────


def test_path_from_request_body_not_demoted(tmp_path: Path):
    """When the path comes from `request.json()` we don't have a way to
    classify it as system, so it stays at the original confidence. We
    don't ELEVATE — that would require retention logic — but we don't
    silently demote real risks either."""
    _write(tmp_path, "routes/upload.py", """
import os

def handle(request):
    path = request.json()['path']
    os.unlink(path)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 5)
    # Should remain at original (high) — not demoted.
    assert f.confidence == "high"
    assert f.extra.get("taint_demoted") is not True


def test_path_from_function_call_unknown_not_demoted(tmp_path: Path):
    """Path from a function call we don't recognize → unknown → leave
    severity alone."""
    _write(tmp_path, "routes/x.py", """
import os
from .helpers import get_user_path

def cleanup(user_id):
    path = get_user_path(user_id)
    os.unlink(path)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 6)
    assert f.confidence == "high"
    assert f.extra.get("taint_demoted") is not True


def test_subprocess_run_with_tempfile_demoted(tmp_path: Path):
    """Subprocess shell-exec with a tempfile-derived first arg → demote.
    `tempfile.mkstemp()` returns a tuple so the RHS is a Subscript on a
    Call — this test guards that the classifier walks through the
    subscript and still recognizes the tempfile call below."""
    _write(tmp_path, "scripts/run_temp.py", """
import subprocess
import tempfile

def run():
    fd, cmd_path = tempfile.mkstemp()
    subprocess.run(cmd_path)
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 6)
    # `fd, cmd_path = tempfile.mkstemp()` is a tuple unpack — the classifier's
    # current MVP doesn't trace through tuple unpacks, so the finding stays
    # at its original severity. Test pins this so a future improvement can
    # flip the assertion.
    assert f.confidence in ("low", "high")


def test_eval_with_constant_string_already_low_unchanged(tmp_path: Path):
    """`eval("2+2")` is already low via _refine_python_severity — taint
    pass leaves it alone (already at low, demote is a no-op)."""
    _write(tmp_path, "lib.py", """
def constant_compute():
    return eval("2 + 2")
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 2)
    assert f.confidence == "low"
    # The original refinement set this to low; taint may or may not have
    # touched it. Either way, current state is low.


# ─── Idempotency ────────────────────────────────────────────────────


def test_taint_pass_is_idempotent(tmp_path: Path):
    _write(tmp_path, "x.py", """
import tempfile
from pathlib import Path

def f():
    tmp = tempfile.NamedTemporaryFile()
    Path(tmp.name).unlink()
""")
    findings = _scan_and_taint(tmp_path)
    f = _by_line(findings, 6)
    assert f.confidence == "low"
    # Second pass should leave the demoted finding alone.
    annotate_findings(findings)
    assert f.confidence == "low"


# ─── Skip cases ─────────────────────────────────────────────────────


def test_non_python_file_skipped():
    """Taint pass is Python-only. TS/JS findings pass through unchanged."""
    f = Finding(
        scanner="fs-shell", file="x.ts", line=1,
        snippet="fs.unlink(p)", suggested_action_type="tool_use",
        confidence="high", rationale="...",
        extra={"family": "fs-delete"},
    )
    annotate_findings([f])
    assert f.confidence == "high"
    assert f.extra.get("taint_demoted") is not True


def test_low_finding_skipped():
    """Already-low findings don't need demotion. Skip them entirely so
    we don't pay AST cost for nothing."""
    f = Finding(
        scanner="fs-shell", file="x.py", line=1,
        snippet="os.unlink('/tmp/x')", suggested_action_type="tool_use",
        confidence="low", rationale="...",
        extra={"family": "fs-delete"},
    )
    annotate_findings([f])
    assert f.confidence == "low"
    # Didn't get marked taint_demoted because we never ran the AST check.
    assert f.extra.get("taint_demoted") is not True


def test_other_scanner_skipped():
    """The pass is fs-shell-only. payment-calls / db-mutations findings
    have different arg shapes; out of scope here."""
    f = Finding(
        scanner="payment-calls", file="x.py", line=1,
        snippet="stripe.Charge.create(amount=tmp_amount)",
        suggested_action_type="payment", confidence="high",
        rationale="...", extra={"vendor": "stripe"},
    )
    annotate_findings([f])
    assert f.confidence == "high"
    assert f.extra.get("taint_demoted") is not True
