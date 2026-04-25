"""Enforce the post-scan communication rules across all user-facing copy.

Source of truth: docs/SCAN_COMMUNICATION_RULES.md +
packages/policies/scan_output.base.v1.yaml.

The rules these tests guard:
  - No forbidden words in markdown headlines (^#+ ) of START_HERE.md
  - No forbidden words in CLI stdout
  - max_wrap_targets cap is honored
  - default-hidden paths land in hidden_counter, not top findings
  - label_map keys translate from internal action_type to plain English
"""
from __future__ import annotations

import re
from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.findings import Finding
from supervisor_discover.policy_loader import load_scan_output_policy
from supervisor_discover.scanners import apply_default_hidden, scan_all
from supervisor_discover.start_here import (
    build_start_here,
    render_cli_start_here,
    render_start_here_md,
)
from supervisor_discover.summary import AgentChokepoint, RepoSummary, build_summary

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def _all_headlines(md: str) -> list[str]:
    """Return every `^#+` markdown headline in `md` (just the headline text)."""
    return [m.group(0).strip() for m in re.finditer(r"^#{1,6}\s.+$", md, re.MULTILINE)]


# 1. Forbidden words

def test_no_forbidden_words_in_start_here_headlines():
    policy = load_scan_output_policy()
    forbidden = [w.lower() for w in policy["forbidden_words"]]
    # Build a realistic START_HERE.md and check every headline.
    findings = validate(scan_all(FLASK_FIXTURE))
    visible, hidden = apply_default_hidden(findings, FLASK_FIXTURE)
    summary = build_summary(visible, hidden_counts=hidden)
    sh = build_start_here(summary, visible)
    md = render_start_here_md(sh)
    for headline in _all_headlines(md):
        lower = headline.lower()
        for word in forbidden:
            assert word not in lower, (
                f"forbidden word {word!r} appeared in headline: {headline!r}"
            )


def test_no_forbidden_words_in_cli_output():
    policy = load_scan_output_policy()
    forbidden = [w.lower() for w in policy["forbidden_words"]]
    findings = validate(scan_all(FLASK_FIXTURE))
    visible, hidden = apply_default_hidden(findings, FLASK_FIXTURE)
    summary = build_summary(visible, hidden_counts=hidden)
    sh = build_start_here(summary, visible)
    text = "\n".join(render_cli_start_here(sh, elapsed_s=0.0, root="x")).lower()
    for word in forbidden:
        assert word not in text, f"forbidden word {word!r} appeared in CLI output"


# 2. Wrap-target cap

def test_max_wrap_targets_honored_from_policy():
    policy = load_scan_output_policy()
    cap = policy["max_wrap_targets"]
    cps = [
        AgentChokepoint(file=f"src/orch{i}.py", line=i + 1, kind="agent-class", label=f"Orch{i}")
        for i in range(cap + 5)
    ]
    sh = build_start_here(RepoSummary(agent_chokepoints=cps), [])
    assert len(sh.top_wrap_targets) == cap


# 3. Label map

def test_label_map_translates_internal_categories():
    policy = load_scan_output_policy()
    labels = policy["label_map"]
    # Every internal tier the scanner emits must have a human label.
    expected_keys = {"payment", "tool_use", "data_access", "general"}
    missing = expected_keys - set(labels.keys())
    assert not missing, f"label_map missing keys: {missing}"
    # Labels must be lower-case English phrases (not internal codes).
    for key, label in labels.items():
        assert label != key, f"label_map[{key!r}] still uses the internal code"
        assert label.islower() or " " in label, f"label_map[{key!r}] uses non-plain casing"


# 4. Hidden paths routed to counter

def test_default_hidden_paths_routed_to_counter_not_visible():
    f_test = Finding(
        scanner="fs-shell", file="repo/tests/test_x.py", line=1, snippet="subprocess.run(",
        suggested_action_type="tool_use", confidence="high", rationale="...", extra={},
    )
    f_legacy = Finding(
        scanner="fs-shell", file="repo/legacy/old.py", line=1, snippet="subprocess.run(",
        suggested_action_type="tool_use", confidence="high", rationale="...", extra={},
    )
    f_prod = Finding(
        scanner="fs-shell", file="repo/src/main.py", line=1, snippet="subprocess.run(",
        suggested_action_type="tool_use", confidence="high", rationale="...", extra={},
    )
    visible, hidden = apply_default_hidden([f_test, f_legacy, f_prod], None)
    visible_files = {f.file for f in visible}
    assert "repo/src/main.py" in visible_files
    assert "repo/tests/test_x.py" not in visible_files
    assert "repo/legacy/old.py" not in visible_files
    assert hidden.get("tests") == 1
    assert hidden.get("legacy") == 1


def test_include_flag_re_enables_hidden_category():
    f_test = Finding(
        scanner="fs-shell", file="repo/tests/test_x.py", line=1, snippet="subprocess.run(",
        suggested_action_type="tool_use", confidence="high", rationale="...", extra={},
    )
    visible, hidden = apply_default_hidden([f_test], None, include_tests=True)
    assert any(f.file == "repo/tests/test_x.py" for f in visible)
    # Counter must NOT count it once it's been re-included.
    assert hidden.get("tests", 0) == 0
