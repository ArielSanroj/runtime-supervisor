"""LLM-ready prompts for findings.

A prompt is a copy-paste-able instruction set. The user pastes it into
Cursor / Claude Code and the agent edits the file. Two invariants we
care about:

  1. The prompt names the exact target (file:line + snippet) so the
     LLM doesn't have to grep.
  2. The CHANGE block carries a fenced code skeleton in the *right
     language*, anchored to the right action_type's policy.
"""
from __future__ import annotations

from supervisor_discover.findings import Finding
from supervisor_discover.prompts import prompt_for, prompt_for_group


def _f(scanner: str, *, file: str = "/repo/src/x.ts", line: int = 42,
       snippet: str = "client.calls.create({})", action: str = "tool_use",
       confidence: str = "high", rationale: str = "agent rationale here",
       **extra) -> Finding:
    return Finding(
        scanner=scanner, file=file, line=line, snippet=snippet,
        suggested_action_type=action, confidence=confidence,  # type: ignore[arg-type]
        rationale=rationale, extra=extra,
    )


def test_prompt_has_required_sections():
    p = prompt_for(_f("voice-actions"))
    for section in ("GOAL:", "CONTEXT:", "TARGET:", "CHANGE:", "CONSTRAINTS:", "Confirm with the diff."):
        assert section in p, f"missing section {section!r}"


def test_prompt_includes_file_and_line():
    p = prompt_for(_f("voice-actions", file="/repo/src/voice/index.ts", line=105))
    assert "src/voice/index.ts:105" in p
    assert "Line: 105" in p


def test_prompt_picks_typescript_for_ts_files():
    p = prompt_for(_f("voice-actions", file="/repo/src/foo.ts"))
    assert "```ts" in p
    assert "@runtime-supervisor/guards" in p


def test_prompt_picks_python_for_py_files():
    p = prompt_for(_f("llm-calls", file="/repo/agent.py", action="tool_use"))
    assert "```python" in p
    assert "supervisor_guards" in p


def test_prompt_carries_action_type_in_decorator():
    p = prompt_for(_f("payment-calls", action="payment"))
    assert "@supervised('payment')" in p or "supervised('payment'" in p


def test_prompt_includes_shadow_mode_constraint():
    p = prompt_for(_f("db-mutations", action="data_access"))
    assert "SUPERVISOR_ENFORCEMENT_MODE=shadow" in p
    assert "must NOT block" in p


def test_prompt_quotes_snippet_for_target():
    p = prompt_for(_f("voice-actions", snippet="api.twilio.com/Accounts/.../Calls"))
    assert "Snippet: `api.twilio.com" in p


def test_prompt_truncates_oversized_snippet():
    huge = "x" * 500
    p = prompt_for(_f("llm-calls", snippet=huge))
    # Snippet section must contain the ellipsis marker, not the full 500 chars
    assert "…" in p or "..." in p
    assert huge not in p


def test_prompt_includes_rationale_in_context():
    p = prompt_for(_f("voice-actions", rationale="ElevenLabs voice synthesis — vishing pair."))
    assert "ElevenLabs voice synthesis" in p


def test_grouped_prompt_lists_all_targets_when_under_cap():
    findings = [
        _f("db-mutations", file=f"/repo/src/db/{i}.ts", line=10 + i, action="data_access")
        for i in range(5)
    ]
    p = prompt_for_group(findings, label="Gate 5 business mutations", action_type="data_access")
    for i in range(5):
        assert f"src/db/{i}.ts:{10 + i}" in p


def test_grouped_prompt_truncates_at_cap_and_points_to_findings_json():
    findings = [
        _f("db-mutations", file=f"/repo/src/db/f{i}.ts", line=i, action="data_access")
        for i in range(20)
    ]
    p = prompt_for_group(findings, label="Gate 20 mutations", action_type="data_access")
    assert "and 8 more" in p
    assert "findings.json" in p


def test_grouped_prompt_offers_both_language_patterns():
    findings = [_f("voice-actions") for _ in range(2)]
    p = prompt_for_group(findings, label="Wrap 2 voice call-sites", action_type="tool_use")
    assert "```python" in p
    assert "```ts" in p


def test_short_path_strips_absolute_prefix():
    p = prompt_for(_f("voice-actions",
                      file="/Users/me/work/projects/myrepo/src/foo.ts", line=1))
    assert "/Users/me/work/projects" not in p
    assert "src/foo.ts:1" in p


def test_data_access_pattern_carries_table_and_verb_payload():
    p = prompt_for(_f("db-mutations", action="data_access", file="/repo/src/q.py"))
    assert "table" in p.lower()
    assert "verb" in p.lower()
