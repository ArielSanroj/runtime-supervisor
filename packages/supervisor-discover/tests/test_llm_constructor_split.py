"""Split LLM client construction (no prompt yet) from invocation
(prompt is in flight). Construction stays as a `low`-confidence
informational signal; invocation is the `high`-confidence wrap target.

Background: scanning langchain produced 14 `high` LLM call-sites that
were every one of them `openai.OpenAI(api_key=...)` — class
constructors, not LLM calls. Wrapping a constructor doesn't gate prompt
injection; the actual chokepoint is the method call that carries the
prompt (`client.chat.completions.create(...)`). Lumping them together
inflated the report and pointed users at the wrong wrap point.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding
from supervisor_discover.scanners import llm_calls


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _kinds(findings: list[Finding]) -> list[tuple[str, str]]:
    return [
        ((f.extra or {}).get("kind", "?"), f.confidence)
        for f in findings
        if f.scanner == "llm-calls"
    ]


def test_python_constructor_emits_low_construction(tmp_path: Path):
    _write(tmp_path, "agent.py", """
import openai

client = openai.OpenAI(api_key="key")
""")
    findings = llm_calls.scan(tmp_path)
    kinds = _kinds(findings)
    assert ("construction", "low") in kinds, kinds
    # And no high finding (no prompt is yet in flight)
    assert not any(f.confidence == "high" for f in findings)


def test_python_invocation_emits_high(tmp_path: Path):
    _write(tmp_path, "agent.py", """
import openai

def go(prompt):
    return openai.chat.completions.create(messages=[{"role":"user","content":prompt}])
""")
    findings = llm_calls.scan(tmp_path)
    kinds = _kinds(findings)
    assert ("invocation", "high") in kinds, kinds


def test_python_constructor_and_invocation_both_emit(tmp_path: Path):
    """A repo with both shapes must emit both, with their right tier."""
    _write(tmp_path, "agent.py", """
import openai

client = openai.OpenAI(api_key="x")

def go(prompt):
    return client.chat.completions.create(messages=[{"role":"user","content":prompt}])
""")
    findings = llm_calls.scan(tmp_path)
    kinds = _kinds(findings)
    assert ("construction", "low") in kinds, kinds
    # `client.chat.completions.create` lands as medium because `client` is
    # a local variable — vendor-specific method, file-imports-LLM heuristic.
    assert any(f.confidence == "medium" for f in findings), kinds


def test_ts_constructor_emits_low(tmp_path: Path):
    _write(tmp_path, "agent.ts", """
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_KEY });
""")
    findings = llm_calls.scan(tmp_path)
    kinds = _kinds(findings)
    assert ("construction", "low") in kinds, kinds
    assert not any(f.confidence == "high" for f in findings)


def test_ts_invocation_emits_high(tmp_path: Path):
    _write(tmp_path, "agent.ts", """
import OpenAI from "openai";

const client = new OpenAI();
async function go(prompt: string) {
  return await client.chat.completions.create({ messages: [{ role: "user", content: prompt }] });
}
""")
    findings = llm_calls.scan(tmp_path)
    kinds = _kinds(findings)
    # The method-call regex fires for `chat.completions.create(`. The
    # `new OpenAI()` constructor on the previous line is reported as low,
    # but the method call carries the prompt — that's the high finding.
    assert any(c == "high" for _, c in kinds), kinds
