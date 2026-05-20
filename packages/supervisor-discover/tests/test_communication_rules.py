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


def test_benchmark_noise_paths_hidden_from_preview():
    """Regression coverage for the 10-repo benchmark noise buckets:
    Cal.com integration tests, Supabase generated Monaco/registry/examples,
    and Chatwoot CI SQL should not be visible preview findings."""
    noisy = [
        Finding(
            scanner="db-mutations",
            file="repo/packages/features/foo.repository.integration-test.ts",
            line=1,
            snippet="prisma.user.create",
            suggested_action_type="account_change",
            confidence="high",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="fs-shell",
            file="repo/apps/studio/public/monaco-editor/base/worker/workerMain.js",
            line=1,
            snippet="new Function(",
            suggested_action_type="tool_use",
            confidence="high",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="mcp-tools",
            file="repo/examples/edge-functions/simple-mcp-server/index.ts",
            line=1,
            snippet="server.registerTool(",
            suggested_action_type="tool_use",
            confidence="high",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="http-routes",
            file="repo/apps/ui-library/registry/default/app/auth/confirm/route.ts",
            line=1,
            snippet="export async function GET(",
            suggested_action_type="other",
            confidence="high",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="db-mutations",
            file="repo/.circleci/setup_chatwoot.sql",
            line=1,
            snippet="UPDATE pg_database SET",
            suggested_action_type="other",
            confidence="medium",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="db-mutations",
            file="repo/docker/volumes/db/webhooks.sql",
            line=1,
            snippet="CREATE TRIGGER",
            suggested_action_type="other",
            confidence="high",
            rationale="...",
            extra={},
        ),
        Finding(
            scanner="fs-shell",
            file="repo/packages/cli/medusa-cli/src/commands/new.ts",
            line=1,
            snippet="execa(",
            suggested_action_type="tool_use",
            confidence="high",
            rationale="...",
            extra={},
        ),
    ]
    visible, hidden = apply_default_hidden(noisy, None)
    assert visible == []
    assert hidden.get("tests") == 1
    assert hidden.get("generated") == 1
    assert hidden.get("examples") == 1
    assert hidden.get("templates") == 1
    assert hidden.get("ci") == 1
    assert hidden.get("infra") == 1
    assert hidden.get("tooling") == 1


# 5. Per-language risk-card copy (regression: obscura repro on /scan)

def test_code_eval_card_does_not_recommend_python_only_advice_for_js():
    """A `new Function(` finding in a `.js` file must not be told to replace
    it with `ast.literal_eval` — that's a Python-stdlib function and
    nonsensical advice in JavaScript. Reproduces the obscura `/scan` bug
    where a JS bundle got Python-only remediation copy."""
    js_finding = Finding(
        scanner="fs-shell",
        file="repo/obscura-js/js/bootstrap.js",
        line=2691,
        snippet="new Function(",
        suggested_action_type="tool_use",
        confidence="high",
        rationale="...",
        extra={"family": "code-eval"},
    )
    summary = RepoSummary(agent_path_present=False)
    sh = build_start_here(summary, [js_finding])
    eval_risk = next(
        (r for r in sh.top_risks if r.family == "fs-shell-code-eval"),
        None,
    )
    assert eval_risk is not None, (
        f"code-eval card must surface — got families "
        f"{[r.family for r in sh.top_risks]}"
    )
    do_lower = eval_risk.do_this_now.lower()
    assert "ast.literal_eval" not in do_lower, (
        f"JS finding must not mention ast.literal_eval — got: "
        f"{eval_risk.do_this_now!r}"
    )
    # Sanity: the JS-flavored copy points at a JS-side parser library.
    assert ("jsep" in do_lower) or ("expr-eval" in do_lower), (
        f"JS code-eval card should point at a JS parser lib — got: "
        f"{eval_risk.do_this_now!r}"
    )


def test_code_eval_card_keeps_python_advice_for_py_findings():
    """Mirror of the JS test: a `.py` file with `eval(...)` must still get
    the Python-flavored advice (ast.literal_eval / safer-eval)."""
    py_finding = Finding(
        scanner="fs-shell",
        file="repo/api/admin.py",
        line=20,
        snippet="eval(payload)",
        suggested_action_type="tool_use",
        confidence="high",
        rationale="...",
        extra={"family": "code-eval"},
    )
    summary = RepoSummary(agent_path_present=False)
    sh = build_start_here(summary, [py_finding])
    eval_risk = next(
        (r for r in sh.top_risks if r.family == "fs-shell-code-eval"),
        None,
    )
    assert eval_risk is not None
    assert "ast.literal_eval" in eval_risk.do_this_now, (
        f"Python finding must keep Python advice — got: "
        f"{eval_risk.do_this_now!r}"
    )


def test_js_scanner_rationale_does_not_say_runs_as_python():
    """`_scan_js` must use `_RATIONALES_JS` for code-eval, not
    `_RATIONALES`. Otherwise the rationale string in `findings.json` /
    `report.md` (Builder export) leaks the Python-only copy."""
    from supervisor_discover.scanners.fs_shell import _RATIONALES_JS

    rationale = _RATIONALES_JS["code-eval"].lower()
    assert "as javascript" in rationale
    assert "as python" not in rationale
    assert "ast.literal_eval" not in rationale
