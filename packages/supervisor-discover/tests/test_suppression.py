"""Tests for `.supervisor-ignore`.

Without suppressions every re-scan re-lists the same findings the dev
already triaged. The reviewer specifically flagged this on supervincent
(`setup.py:58` build script) and castor-1 (`e14_data.py:564` tempfile
path) — both are real findings with no LLM reachability that kept
showing up despite explicit verification.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.suppression import (
    SuppressionRule,
    annotate_findings,
    is_suppressed,
    load_rules,
    stale_rules,
)


def _f(file: str, line: int, scanner: str = "fs-shell") -> Finding:
    return Finding(
        scanner=scanner, file=file, line=line, snippet="x",
        suggested_action_type="tool_use", confidence="high",
        rationale="...", extra={"family": "shell-exec"},
    )


def _write_ignore(repo: Path, body: str) -> None:
    (repo / ".supervisor-ignore").write_text(body)


# ─── Parser ─────────────────────────────────────────────────────────


def test_load_rules_skips_blank_and_comment(tmp_path: Path):
    _write_ignore(tmp_path, """
# Header comment
# another comment

backend/setup.py:58  build-script  ariel  2026-04-26

# trailing

""")
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    r = rules[0]
    assert r.pattern == "backend/setup.py"
    assert r.line == 58
    assert r.reason == "build-script"
    assert r.reviewer == "ariel"
    assert r.date == "2026-04-26"


def test_load_rules_no_file_returns_empty(tmp_path: Path):
    assert load_rules(tmp_path) == []


def test_load_rules_path_without_line(tmp_path: Path):
    _write_ignore(tmp_path, "backend/installer.py  install-time-only\n")
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].pattern == "backend/installer.py"
    assert rules[0].line is None


def test_load_rules_glob_pattern(tmp_path: Path):
    _write_ignore(tmp_path, "scripts/**  build-only  ariel\n")
    rules = load_rules(tmp_path)
    assert rules[0].pattern == "scripts/**"
    assert rules[0].line is None


def test_load_rules_rejects_line_without_reason(tmp_path: Path):
    """Suppressing a finding without a stated reason is the path to "junk
    drawer" suppressions. Parser drops the rule silently."""
    _write_ignore(tmp_path, "backend/setup.py:58\n")
    rules = load_rules(tmp_path)
    assert rules == []


# ─── Matcher ────────────────────────────────────────────────────────


def test_match_exact_path_and_line(tmp_path: Path):
    _write_ignore(tmp_path, "src/x.py:42  reason  ariel\n")
    src = tmp_path / "src" / "x.py"
    src.parent.mkdir()
    src.touch()
    findings = [_f(str(src), 42), _f(str(src), 99)]
    annotate_findings(findings, load_rules(tmp_path), tmp_path)
    assert is_suppressed(findings[0])
    assert not is_suppressed(findings[1])


def test_match_path_without_line_covers_all_lines(tmp_path: Path):
    _write_ignore(tmp_path, "src/installer.py  install\n")
    src = tmp_path / "src" / "installer.py"
    src.parent.mkdir()
    src.touch()
    findings = [_f(str(src), 5), _f(str(src), 100)]
    annotate_findings(findings, load_rules(tmp_path), tmp_path)
    assert is_suppressed(findings[0])
    assert is_suppressed(findings[1])


def test_match_glob_double_star(tmp_path: Path):
    _write_ignore(tmp_path, "scripts/**  build-only\n")
    a = tmp_path / "scripts" / "deploy.py"
    a.parent.mkdir()
    a.touch()
    b = tmp_path / "scripts" / "infra" / "bootstrap.py"
    b.parent.mkdir(parents=True)
    b.touch()
    findings = [_f(str(a), 1), _f(str(b), 1), _f(str(tmp_path / "src" / "main.py"), 1)]
    annotate_findings(findings, load_rules(tmp_path), tmp_path)
    assert is_suppressed(findings[0])
    assert is_suppressed(findings[1])
    assert not is_suppressed(findings[2])


def test_match_carries_reason_and_rule(tmp_path: Path):
    _write_ignore(tmp_path, "src/x.py:1  build-script  ariel  2026-04-26\n")
    src = tmp_path / "src" / "x.py"
    src.parent.mkdir()
    src.touch()
    f = _f(str(src), 1)
    annotate_findings([f], load_rules(tmp_path), tmp_path)
    assert f.extra["suppressed"] is True
    assert f.extra["suppression_reason"] == "build-script"
    assert "build-script" in f.extra["suppressed_by"]
    assert "ariel" in f.extra["suppressed_by"]


def test_first_match_wins(tmp_path: Path):
    _write_ignore(tmp_path, """
src/x.py:42  specific-reason  ariel
src/x.py    generic-reason   ariel
""")
    src = tmp_path / "src" / "x.py"
    src.parent.mkdir()
    src.touch()
    f = _f(str(src), 42)
    annotate_findings([f], load_rules(tmp_path), tmp_path)
    assert f.extra["suppression_reason"] == "specific-reason"


def test_annotate_is_idempotent(tmp_path: Path):
    _write_ignore(tmp_path, "src/x.py:1  build  ariel\n")
    src = tmp_path / "src" / "x.py"
    src.parent.mkdir()
    src.touch()
    f = _f(str(src), 1)
    rules = load_rules(tmp_path)
    annotate_findings([f], rules, tmp_path)
    first_rule = f.extra["suppressed_by"]
    annotate_findings([f], rules, tmp_path)
    assert f.extra["suppressed_by"] == first_rule


# ─── Stale detection ────────────────────────────────────────────────


def test_stale_rules_returns_unmatched(tmp_path: Path):
    """A rule that never matches anything in this scan is suspicious — the
    call probably moved or was deleted, and the suppression now hides a
    different reality. The renderer can warn the dev."""
    _write_ignore(tmp_path, """
src/x.py:1  reason  ariel
src/y.py:1  reason  ariel
""")
    src_x = tmp_path / "src" / "x.py"
    src_x.parent.mkdir()
    src_x.touch()
    rules = load_rules(tmp_path)
    f = _f(str(src_x), 1)
    matches = annotate_findings([f], rules, tmp_path)
    stale = stale_rules(rules, matches)
    assert len(stale) == 1
    assert stale[0].pattern == "src/y.py"
