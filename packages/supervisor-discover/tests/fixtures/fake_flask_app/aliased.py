"""Fixture for alias handling: the scanner must catch these despite the aliases."""
from __future__ import annotations

import anthropic as _anthropic
import stripe as _stripe
from openai import OpenAI as _OpenAI


def do_refund(amount: int):
    return _stripe.Refund.create(amount=amount)


def do_llm(prompt: str):
    client = _anthropic.Anthropic()
    return client.messages.create(model="claude-sonnet-4-6", messages=[{"role": "user", "content": prompt}])


def do_openai():
    return _OpenAI().chat.completions.create(model="gpt-4", messages=[])


def not_an_llm_call_even_though_this_file_imports_one():
    # stream_with_context + generate() are Flask/stdlib shaped — the OLD
    # loose-substring detector wrongly matched these; the new detector
    # only matches calls whose root resolves to an LLM SDK.
    from flask import stream_with_context

    def generate():
        yield "hi"

    return stream_with_context(generate())
