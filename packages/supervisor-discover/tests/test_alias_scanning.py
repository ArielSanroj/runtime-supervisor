"""Regression: alias-resolved scanning catches `import stripe as _stripe`
and doesn't fire on Flask helpers in LLM-importing files."""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all

FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def test_detects_aliased_stripe_refund():
    findings = scan_all(FIXTURE)
    payments = [f for f in findings if f.scanner == "payment-calls"]
    # The aliased.py fixture has _stripe.Refund.create — old detector missed it.
    aliased = [f for f in payments if "aliased.py" in f.file]
    assert len(aliased) == 1, f"expected 1 aliased refund finding, got {aliased}"
    assert aliased[0].suggested_action_type == "refund"


def test_detects_aliased_anthropic_and_openai():
    findings = scan_all(FIXTURE)
    llms = [f for f in findings if f.scanner == "llm-calls" and "aliased.py" in f.file]
    methods = {f.snippet for f in llms}
    # Both constructors (high confidence via alias) should fire.
    assert any("anthropic.Anthropic" in m for m in methods), methods
    assert any("openai.OpenAI" in m.lower() or "OpenAI" in m for m in methods), methods
    # And the variable-assigned client.messages.create should come through
    # at medium confidence.
    msgs = [f for f in llms if "messages.create" in f.snippet]
    assert len(msgs) == 1, methods
    assert msgs[0].confidence == "medium"


def test_does_not_flag_flask_stream_with_context_as_llm():
    findings = scan_all(FIXTURE)
    llms = [f for f in findings if f.scanner == "llm-calls" and "aliased.py" in f.file]
    # stream_with_context and the nested generate() are NOT LLM calls.
    for f in llms:
        assert "stream_with_context" not in f.snippet
        assert f.snippet != "generate(...)"  # bare generate() must not match
