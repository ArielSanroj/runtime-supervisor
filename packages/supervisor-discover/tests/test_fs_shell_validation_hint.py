"""Downgrade fs/shell findings when the same function calls a validation
helper before the destructive op.

Background: the langchain scan flagged
`shutil.rmtree(full_path)` on `anthropic_tools.py:1018` as `high`, but
the surrounding method calls `_validate_and_resolve_path(path)` first —
the user already filters for traversal. Reporting it as `high` mixes a
genuine wrap target with a call that has visible local guards.

This is heuristic, not taint tracking. The detector only checks "is
there a validation-shaped call earlier in the same function". The
finding stays in the report (so it's reviewable), but drops to `medium`
with `extra.has_local_validation` set to the validator's name.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import fs_shell


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _scan(tmp: Path):
    return fs_shell._scan_python(tmp / "agent.py", (tmp / "agent.py").read_text())


def test_validation_before_rmtree_downgrades_to_medium(tmp_path: Path):
    _write(tmp_path, "agent.py", """
import shutil

class Tools:
    def _validate_and_resolve_path(self, p):
        return p

    def delete(self, p):
        full_path = self._validate_and_resolve_path(p)
        shutil.rmtree(full_path)
""")
    findings = _scan(tmp_path)
    rmtree = next(f for f in findings if "rmtree" in f.snippet)
    assert rmtree.confidence == "medium"
    assert (rmtree.extra or {}).get("has_local_validation") == "_validate_and_resolve_path"


def test_validation_after_rmtree_does_not_downgrade(tmp_path: Path):
    """Validation that runs *after* the destructive call is no protection
    at all — the rmtree fires first. Stay at high."""
    _write(tmp_path, "agent.py", """
import shutil

def delete(p):
    shutil.rmtree(p)
    _validate_path(p)
""")
    findings = _scan(tmp_path)
    rmtree = next(f for f in findings if "rmtree" in f.snippet)
    assert rmtree.confidence == "high"
    assert "has_local_validation" not in (rmtree.extra or {})


def test_no_validation_keeps_high(tmp_path: Path):
    """Regression: a destructive call with no nearby validation must stay
    at high so it surfaces as a wrap target."""
    _write(tmp_path, "agent.py", """
import shutil

def delete(p):
    shutil.rmtree(p)
""")
    findings = _scan(tmp_path)
    rmtree = next(f for f in findings if "rmtree" in f.snippet)
    assert rmtree.confidence == "high"
    assert "has_local_validation" not in (rmtree.extra or {})


def test_validation_in_different_function_does_not_downgrade(tmp_path: Path):
    """Validation in a sibling function isn't reachable in the call's
    enclosing scope — don't credit it. Stay at high."""
    _write(tmp_path, "agent.py", """
import shutil

def _validate_path(p):
    return p

def delete(p):
    shutil.rmtree(p)
""")
    findings = _scan(tmp_path)
    rmtree = next(f for f in findings if "rmtree" in f.snippet)
    assert rmtree.confidence == "high"


def test_check_args_before_subprocess_downgrades(tmp_path: Path):
    """Subprocess shell-exec also picks up the local-validation hint."""
    _write(tmp_path, "agent.py", """
import subprocess

def _check_args(args):
    return args

def run(args):
    safe = _check_args(args)
    subprocess.run(safe)
""")
    findings = _scan(tmp_path)
    sub = next(f for f in findings if "subprocess.run" in f.snippet)
    assert sub.confidence == "medium"
    assert (sub.extra or {}).get("has_local_validation") == "_check_args"


def test_bare_validate_does_not_match(tmp_path: Path):
    """`validate(...)` without a noun suffix is too generic (form
    validation libraries, etc.) — must NOT downgrade."""
    _write(tmp_path, "agent.py", """
import shutil

def validate(thing):
    return thing

def delete(p):
    validate(p)
    shutil.rmtree(p)
""")
    findings = _scan(tmp_path)
    rmtree = next(f for f in findings if "rmtree" in f.snippet)
    assert rmtree.confidence == "high"
    assert "has_local_validation" not in (rmtree.extra or {})
