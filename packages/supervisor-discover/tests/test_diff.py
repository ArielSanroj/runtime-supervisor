"""Tests for `diff.py` and the `--fail-on` CI gate.

The diff is the feature that takes the scanner from "one-off informational
report" to "PR gate that catches new risk before merge". These tests pin
the contract: stable IDs match across reformats, severity changes get
caught, the budget logic refuses any new high-confidence finding under
`new-high`.
"""
from __future__ import annotations

import json
from pathlib import Path

from supervisor_discover.diff import (
    diff_payloads,
    exceeds_budget,
    load_payload,
    render_text,
)
from supervisor_discover.findings import Finding, assign_ids, stable_id


def _payload(findings: list[Finding]) -> dict:
    return {
        "schema_version": "1.0",
        "findings": [f.to_dict() for f in findings],
    }


def _f(file: str, line: int, scanner: str = "fs-shell",
       confidence: str = "high", snippet: str = "subprocess.run(",
       suppressed: bool = False) -> Finding:
    extra: dict = {"family": "shell-exec"}
    if suppressed:
        extra["suppressed"] = True
        extra["suppression_reason"] = "test"
    f = Finding(
        scanner=scanner, file=file, line=line, snippet=snippet,
        suggested_action_type="tool_use", confidence=confidence,
        rationale="...", extra=extra,
    )
    assign_ids([f])
    return f


# ─── ID stability ──────────────────────────────────────────────────


def test_stable_id_survives_whitespace_changes():
    """Same call site, different whitespace inside the snippet → same ID."""
    a = stable_id("fs-shell", "/repo/x.py", 42, "subprocess.run(  cmd  )")
    b = stable_id("fs-shell", "/repo/x.py", 42, "subprocess.run(cmd)")
    assert a == b


def test_stable_id_changes_on_call_target():
    """Different identifier on the same line → different ID, because it's a
    different finding."""
    a = stable_id("fs-shell", "/repo/x.py", 42, "subprocess.run(cmd)")
    b = stable_id("fs-shell", "/repo/x.py", 42, "subprocess.Popen(cmd)")
    assert a != b


def test_stable_id_uses_relative_path_when_repo_root_provided(tmp_path: Path):
    """A repo cloned to a different absolute path between scans must not
    invalidate IDs. Using `repo_root` strips the variable parent dir."""
    a = stable_id("fs-shell", str(tmp_path / "src/x.py"), 1, "open(p)", repo_root=tmp_path)
    other = Path("/some/other/parent")
    other.mkdir(parents=True, exist_ok=True) if False else None  # purely synthetic
    b = stable_id("fs-shell", "/some/other/parent/src/x.py", 1, "open(p)", repo_root=Path("/some/other/parent"))
    assert a == b


def test_assign_ids_is_idempotent():
    f = _f("/r/x.py", 1)
    first = f.id
    assign_ids([f])
    assert f.id == first


# ─── Diff classification ──────────────────────────────────────────


def test_diff_added_finding():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 1)])
    result = diff_payloads(base, cur)
    assert len(result.added) == 1
    assert result.removed == []
    assert result.changed == []


def test_diff_removed_finding():
    base = _payload([_f("/r/x.py", 1)])
    cur = _payload([])
    result = diff_payloads(base, cur)
    assert len(result.removed) == 1
    assert result.added == []


def test_diff_severity_change_lands_in_changed():
    base = _payload([_f("/r/x.py", 1, confidence="medium")])
    # Same id (same scanner/file/line/snippet) but confidence shifted.
    cur = _payload([_f("/r/x.py", 1, confidence="high")])
    result = diff_payloads(base, cur)
    assert result.added == [] and result.removed == []
    assert len(result.changed) == 1
    b, c = result.changed[0]
    assert b.confidence == "medium" and c.confidence == "high"


def test_diff_unchanged_no_entries():
    base = _payload([_f("/r/x.py", 1)])
    cur = _payload([_f("/r/x.py", 1)])
    result = diff_payloads(base, cur)
    assert result.added == [] and result.removed == [] and result.changed == []


def test_diff_added_sorted_by_severity():
    base = _payload([])
    cur = _payload([
        _f("/r/a.py", 1, confidence="low"),
        _f("/r/b.py", 1, confidence="high"),
        _f("/r/c.py", 1, confidence="medium"),
    ])
    result = diff_payloads(base, cur)
    severities = [r.confidence for r in result.added]
    assert severities == ["high", "medium", "low"]


# ─── Render ────────────────────────────────────────────────────────


def test_render_text_no_changes_says_so_explicitly():
    result = diff_payloads(_payload([]), _payload([]))
    out = render_text(result)
    assert "(no changes)" in out


def test_render_text_includes_added_block():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 42, snippet="subprocess.run(cmd)")])
    out = render_text(diff_payloads(base, cur))
    assert "Added:" in out
    assert "+1 high" in out
    assert "subprocess.run" in out


# ─── --fail-on budget ─────────────────────────────────────────────


def test_fail_on_new_high_blocks_new_high():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 1, confidence="high")])
    failed, reason = exceeds_budget(diff_payloads(base, cur), "new-high")
    assert failed
    assert "new-high" in reason


def test_fail_on_new_high_allows_new_medium():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 1, confidence="medium")])
    failed, _ = exceeds_budget(diff_payloads(base, cur), "new-high")
    assert not failed


def test_fail_on_new_medium_blocks_new_medium():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 1, confidence="medium")])
    failed, _ = exceeds_budget(diff_payloads(base, cur), "new-medium")
    assert failed


def test_fail_on_any_blocks_anything_new():
    base = _payload([])
    cur = _payload([_f("/r/x.py", 1, confidence="low")])
    failed, _ = exceeds_budget(diff_payloads(base, cur), "any")
    assert failed


def test_fail_on_never_passes_even_with_new_high():
    base = _payload([])
    cur = _payload([
        _f("/r/x.py", 1, confidence="high"),
        _f("/r/y.py", 2, confidence="high"),
    ])
    failed, _ = exceeds_budget(diff_payloads(base, cur), "never")
    assert not failed


def test_fail_on_unknown_value_is_a_no_op():
    """Unknown --fail-on value returns False with a reason. The CLI won't
    crash, just prints the reason and continues."""
    failed, reason = exceeds_budget(diff_payloads(_payload([]), _payload([])), "junk")
    assert not failed
    assert "unknown" in reason.lower()


# ─── load_payload ─────────────────────────────────────────────────


def test_load_payload_missing_file_returns_empty(tmp_path: Path):
    payload = load_payload(tmp_path / "does-not-exist.json")
    assert payload == {"findings": []}


def test_load_payload_malformed_returns_empty(tmp_path: Path):
    p = tmp_path / "broken.json"
    p.write_text("{ not valid json")
    assert load_payload(p) == {"findings": []}


def test_load_payload_reads_real_file(tmp_path: Path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps({"findings": [{"id": "abc", "scanner": "x", "file": "y", "line": 1,
                                            "snippet": "z", "confidence": "high"}]}))
    payload = load_payload(p)
    assert len(payload["findings"]) == 1
