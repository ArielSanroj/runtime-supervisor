"""Tests for the auto-allowlist extractor.

Without this, the `tool_use.llm-plus-shell-exec.v1.yaml` policy ships with
an undefined `ALLOWED_COMMANDS` symbol and the user has to fill it in by
typing each command from their own repo. The whole point of the scanner
having seen those commands is to feed them back to the user pre-populated.

Tests cover:
  - argv extraction from real fs-shell findings (after a scan)
  - dedup by (cmd, *args)
  - sort stability
  - empty-list fallback when no shell-exec call had a literal argv
  - the path-prefix extractor for fs-write/fs-delete
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.policy_extractors import (
    extract_fs_path_prefixes,
    extract_shell_command_allowlist,
)
from supervisor_discover.scanners import fs_shell


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ─── Shell command allowlist ────────────────────────────────────────


def test_extract_allowlist_from_real_scan(tmp_path: Path):
    _write(tmp_path, "setup.py", """
import subprocess, sys
subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
subprocess.run(["git", "init"])
""")
    findings = fs_shell.scan(tmp_path)
    allowlist = extract_shell_command_allowlist(findings)
    # `sys.executable` is a Name node, not a Constant — so the first call's
    # argv has a non-string element that breaks the literal check. The whole
    # call should be SKIPPED, not partially captured.
    # Only the second call (all string literals) survives.
    assert ["git", "init"] in allowlist


def test_extract_allowlist_full_string_literal(tmp_path: Path):
    _write(tmp_path, "deploy.py", """
import subprocess
subprocess.run(["python", "-m", "pip", "install", "-r", "requirements.txt"])
subprocess.run(["git", "--version"])
""")
    findings = fs_shell.scan(tmp_path)
    allowlist = extract_shell_command_allowlist(findings)
    assert ["python", "-m", "pip", "install", "-r", "requirements.txt"] in allowlist
    assert ["git", "--version"] in allowlist


def test_extract_allowlist_dedups_repeated_calls(tmp_path: Path):
    _write(tmp_path, "loop.py", """
import subprocess
for _ in range(3):
    subprocess.run(["git", "status"])
subprocess.run(["git", "status"])
""")
    findings = fs_shell.scan(tmp_path)
    allowlist = extract_shell_command_allowlist(findings)
    # Two distinct call-sites, same argv → one entry.
    assert allowlist.count(["git", "status"]) == 1


def test_extract_allowlist_empty_when_args_are_variables(tmp_path: Path):
    _write(tmp_path, "dyn.py", """
import subprocess
def run(cmd, args):
    subprocess.run([cmd, *args])
""")
    findings = fs_shell.scan(tmp_path)
    allowlist = extract_shell_command_allowlist(findings)
    assert allowlist == []


def test_extract_allowlist_handles_string_arg(tmp_path: Path):
    """Single-string form `subprocess.run("git log")` → split into argv."""
    _write(tmp_path, "x.py", """
import subprocess
subprocess.run("git log --oneline")
""")
    findings = fs_shell.scan(tmp_path)
    allowlist = extract_shell_command_allowlist(findings)
    assert allowlist == [["git", "log", "--oneline"]]


def test_extract_allowlist_sort_is_stable(tmp_path: Path):
    """Re-runs with the same inputs must return the same allowlist order
    so policy YAMLs don't drift between scans."""
    _write(tmp_path, "a.py", """
import subprocess
subprocess.run(["zzz"])
subprocess.run(["aaa"])
subprocess.run(["mmm"])
""")
    findings = fs_shell.scan(tmp_path)
    a1 = extract_shell_command_allowlist(findings)
    a2 = extract_shell_command_allowlist(findings)
    assert a1 == a2 == [["aaa"], ["mmm"], ["zzz"]]


def test_extract_allowlist_synthetic_findings_without_argv():
    """Findings whose extra has no `argv` key (e.g. variable-arg shell-exec
    calls or older serialized findings) must be silently skipped."""
    findings = [
        Finding(
            scanner="fs-shell", file="x.py", line=1, snippet="subprocess.run(...)",
            suggested_action_type="tool_use", confidence="high",
            rationale="...", extra={"family": "shell-exec"},
        ),
        Finding(
            scanner="fs-shell", file="y.py", line=1, snippet="subprocess.run([...])",
            suggested_action_type="tool_use", confidence="low",
            rationale="...", extra={"family": "shell-exec", "argv": ["pytest"]},
        ),
    ]
    assert extract_shell_command_allowlist(findings) == [["pytest"]]


# ─── Path prefix extractor ──────────────────────────────────────────


def test_path_prefix_extractor_picks_dirs_from_literal_paths():
    findings = [
        Finding(
            scanner="fs-shell", file="x.py", line=1,
            snippet='os.unlink("/tmp/sessions/abc.json")',
            suggested_action_type="tool_use", confidence="high",
            rationale="...", extra={"family": "fs-delete"},
        ),
        Finding(
            scanner="fs-shell", file="y.py", line=1,
            snippet='Path("/var/log/app.log").unlink()',
            suggested_action_type="tool_use", confidence="high",
            rationale="...", extra={"family": "fs-delete"},
        ),
        Finding(
            scanner="fs-shell", file="z.py", line=1,
            snippet="open(path, 'w')",
            suggested_action_type="tool_use", confidence="medium",
            rationale="...", extra={"family": "fs-write"},
        ),  # variable path → skipped
    ]
    prefixes = extract_fs_path_prefixes(findings)
    assert "/tmp/sessions" in prefixes
    assert "/var/log" in prefixes
    # Variable path was correctly skipped — no empty/junk entries.
    assert all(prefixes)


def test_path_prefix_extractor_skips_fstrings():
    """`open(f"/tmp/{user_id}.json")` has dynamic content — too risky to put
    in an allowlist as if it were a literal directory."""
    findings = [
        Finding(
            scanner="fs-shell", file="x.py", line=1,
            snippet='open(f"/tmp/{user_id}.json", "w")',
            suggested_action_type="tool_use", confidence="medium",
            rationale="...", extra={"family": "fs-write"},
        ),
    ]
    assert extract_fs_path_prefixes(findings) == []


# ─── Action enum extraction ────────────────────────────────────────


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


def test_extract_action_enum_from_real_shape(tmp_path: Path):
    """The exact castor-1 shape: `class AgentAction(str, Enum)` with
    string-literal values."""
    from supervisor_discover.policy_extractors import extract_action_enums

    _write(tmp_path, "agent/config.py", """
from enum import Enum

class AgentAction(str, Enum):
    CREATE_INCIDENT = "create_incident"
    DISPATCH_SLA_ALERT = "dispatch_sla_alert"
    MASS_INCIDENT_CREATION = "mass_incident_creation"
""")
    enums = extract_action_enums(tmp_path)
    assert "AgentAction" in enums
    assert "create_incident" in enums["AgentAction"]
    assert "dispatch_sla_alert" in enums["AgentAction"]


def test_extract_skips_status_state_severity_enums(tmp_path: Path):
    from supervisor_discover.policy_extractors import extract_action_enums

    _write(tmp_path, "models.py", """
from enum import Enum

class IncidentStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"

class Severity(str, Enum):
    LOW = "low"
    HIGH = "high"

class TaskKind(str, Enum):
    ALERT = "alert"
    REPORT = "report"
""")
    enums = extract_action_enums(tmp_path)
    # All three enums match action-shape suffixes (Status, Severity, Kind)
    # but contain deny-list tokens — should be excluded.
    assert enums == {}


def test_extract_handles_intenum_and_strenum(tmp_path: Path):
    from supervisor_discover.policy_extractors import extract_action_enums

    _write(tmp_path, "tools.py", """
from enum import IntEnum, StrEnum

class ToolKind(IntEnum):
    SEARCH = 1
    WRITE = 2

class CommandVerb(StrEnum):
    CREATE = "create"
    DELETE = "delete"
""")
    enums = extract_action_enums(tmp_path)
    # ToolKind has "kind" in name → excluded by deny-list.
    # CommandVerb passes (Verb suffix, no deny token).
    assert "CommandVerb" in enums
    assert "create" in enums["CommandVerb"]


def test_extract_uses_member_name_when_no_string_value(tmp_path: Path):
    from supervisor_discover.policy_extractors import extract_action_enums

    _write(tmp_path, "ops.py", """
from enum import Enum, auto

class Operation(Enum):
    INSERT = auto()
    UPDATE = auto()
""")
    enums = extract_action_enums(tmp_path)
    assert "Operation" in enums
    # Falls back to lowercased member names when no string literal.
    assert "insert" in enums["Operation"]
    assert "update" in enums["Operation"]


def test_extract_returns_empty_for_repo_with_no_enums(tmp_path: Path):
    from supervisor_discover.policy_extractors import extract_action_enums

    _write(tmp_path, "lib.py", "def helper(): return 1\n")
    assert extract_action_enums(tmp_path) == {}


def test_render_repo_action_policy_shape():
    from supervisor_discover.policy_extractors import render_repo_action_policy

    enums = {
        "AgentAction": [
            "create_incident", "mass_incident_creation",
            "deploy_witnesses", "track_deadline",
        ],
    }
    yaml_text = render_repo_action_policy(enums, "castor-1")
    assert yaml_text is not None
    assert "name: tool_use.castor-1" in yaml_text
    # Allowed actions list is the union of all enum members.
    assert "create_incident" in yaml_text
    assert "track_deadline" in yaml_text
    # High-blast subset routes to review.
    assert '"mass_incident_creation"' in yaml_text
    assert '"deploy_witnesses"' in yaml_text
    # Rule shapes.
    assert "action-allowlist" in yaml_text
    assert "high-blast-action-review" in yaml_text


def test_render_repo_action_policy_returns_none_when_empty():
    from supervisor_discover.policy_extractors import render_repo_action_policy

    assert render_repo_action_policy({}, "x") is None
