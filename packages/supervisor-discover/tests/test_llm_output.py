"""Tests for the llm-output-without-validation taint detector.

The Andrea/Prodesa class regression: an LLM response (taint source)
flowing to a user-facing sink (return / HTTP response / email body)
without passing through a sanitizer (validate_*, lookup_*, the
PR2 helper assert_entities_in_scope).

Coverage:
  - core taint cases: unguarded / guarded / lookup / sanitizer-after-call
  - sink shapes: return, jsonify, sendmail, slack-reply
  - false-positive traps: keyword-in-comment, keyword-in-string,
    construction-only files, sanitizer aliasing
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners.llm_output import scan


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def _has_finding(findings, *, line: int | None = None) -> bool:
    if line is None:
        return any(True for _ in findings)
    return any(f.line == line for f in findings)


# ── core taint cases ─────────────────────────────────────────────────


def test_chatbot_unguarded_return_flags(tmp_path: Path):
    """LLM call → return verbatim. The simplest regression case."""
    _write(
        tmp_path,
        "chat.py",
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def chat(prompt: str) -> str:\n"
        "    reply = client.messages.create(model='c', messages=[])\n"
        "    return reply.content[0].text\n",
    )
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].extra["sink_kind"] == "return"
    assert findings[0].extra["family"] == "llm-output-without-validation"


def test_assert_entities_in_scope_clears_taint(tmp_path: Path):
    """The PR 2 helper is a recognized sanitizer. After it runs, the
    result is clean and the return must NOT be flagged."""
    _write(
        tmp_path,
        "chat.py",
        "from anthropic import Anthropic\n"
        "from supervisor_guards.scope import assert_entities_in_scope\n"
        "client = Anthropic()\n"
        "def chat(prompt: str, allowed) -> str:\n"
        "    raw = client.messages.create(model='c', messages=[])\n"
        "    safe = assert_entities_in_scope(raw.content[0].text, allowed)\n"
        "    return safe\n",
    )
    findings = scan(tmp_path)
    assert findings == []


def test_lookup_function_is_recognized_as_sanitizer(tmp_path: Path):
    """Naming heuristic — a `lookup_person` / `find_member` call between
    the LLM output and the sink reads as 'caller cross-referenced the
    source-of-truth', taint absorbed."""
    _write(
        tmp_path,
        "chat.py",
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(prompt: str) -> str:\n"
        "    raw = client.chat.completions.create(model='gpt-4', messages=[])\n"
        "    safe = lookup_person(raw.choices[0].message.content)\n"
        "    return safe\n",
    )
    findings = scan(tmp_path)
    assert findings == []


def test_check_in_if_branch_does_not_clear_unguarded_else(tmp_path: Path):
    """The dev called `validate_scope` in the if predicate but the
    fall-through return is still unguarded. The detector flags the
    fall-through return because the var hasn't been re-assigned to a
    sanitized value. Tracks the actual data flow, not the dev's intent."""
    _write(
        tmp_path,
        "chat.py",
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def chat(prompt: str, allowed) -> str:\n"
        "    reply = client.messages.create(model='c', messages=[])\n"
        "    if not validate_scope(reply, allowed):\n"
        "        return 'Out of scope.'\n"
        "    return reply.content[0].text\n",
    )
    findings = scan(tmp_path)
    assert len(findings) >= 1
    # the fall-through return at L7 must be in the list (1-indexed)
    flagged_lines = {f.line for f in findings}
    assert 7 in flagged_lines


# ── sink shapes ──────────────────────────────────────────────────────


def test_jsonify_sink_is_recognized(tmp_path: Path):
    """flask.jsonify is a user-facing sink — taint reaching it must
    fire even without an explicit `return` of the var."""
    _write(
        tmp_path,
        "app.py",
        "import flask\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def chat(prompt):\n"
        "    reply = client.messages.create(model='c', messages=[])\n"
        "    return flask.jsonify({'reply': reply.content[0].text})\n",
    )
    findings = scan(tmp_path)
    assert findings, "expected at least one finding for jsonify sink"


def test_sendmail_sink_is_recognized(tmp_path: Path):
    """If the LLM output ends up in an email body, the recipient is
    still a user reading the assertion as data — must fire."""
    _write(
        tmp_path,
        "mailer.py",
        "import smtplib\n"
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def notify(prompt, addr):\n"
        "    reply = client.messages.create(model='c', messages=[])\n"
        "    smtplib.SMTP('x').sendmail('a@b', addr, reply.content[0].text)\n",
    )
    findings = scan(tmp_path)
    assert findings, "expected at least one finding for sendmail sink"


def test_inline_llm_call_in_return_is_flagged(tmp_path: Path):
    """`return client.messages.create(...).content[0].text` — no
    intermediate var, but the source IS in the return expression. Must
    fire so the dev can't sneak past by inlining."""
    _write(
        tmp_path,
        "chat.py",
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def chat(prompt):\n"
        "    return client.messages.create(model='c', messages=[]).content[0].text\n",
    )
    findings = scan(tmp_path)
    assert findings


# ── false-positive traps ─────────────────────────────────────────────


def test_keyword_in_comment_does_not_fire(tmp_path: Path):
    """A file that mentions `messages.create` in a comment but never
    calls it must produce ZERO findings — AST-first invariant."""
    _write(
        tmp_path,
        "doc.py",
        "import openai\n"
        "# This file used to call client.messages.create in chat() but\n"
        "# we moved the LLM logic out. Don't reintroduce it here.\n"
        "def chat(prompt):\n"
        "    return 'hardcoded reply'\n",
    )
    findings = scan(tmp_path)
    assert findings == []


def test_keyword_in_string_does_not_fire(tmp_path: Path):
    """A docstring or f-string mentioning `client.messages.create` is
    not a call — AST visitor must see through it."""
    _write(
        tmp_path,
        "doc.py",
        "import openai\n"
        "def chat(prompt):\n"
        "    \"\"\"call client.messages.create(...) on the wrapper.\"\"\"\n"
        "    return f'You said: {prompt}'\n",
    )
    findings = scan(tmp_path)
    assert findings == []


def test_construction_only_does_not_fire(tmp_path: Path):
    """`client = Anthropic()` constructs the client but never invokes
    a method. No source → no taint → no finding."""
    _write(
        tmp_path,
        "client.py",
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def get_client():\n"
        "    return client\n",
    )
    findings = scan(tmp_path)
    assert findings == []


def test_repo_with_no_llm_imports_skipped_fast(tmp_path: Path):
    """Empty case: a file with no LLM SDK imports never enters the
    AST walker. No findings — this is the fast-reject path."""
    _write(
        tmp_path,
        "plain.py",
        "def add(a, b):\n"
        "    return a + b\n",
    )
    findings = scan(tmp_path)
    assert findings == []


# ── integration with scan_all ────────────────────────────────────────


def test_llm_output_findings_land_in_scan_all(tmp_path: Path):
    """The scanner must be reachable via the full pipeline — registered
    in __init__, surviving _self_check (which we explicitly bypass for
    llm-output), reaching the final findings list."""
    _write(
        tmp_path,
        "chat.py",
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "def chat(prompt: str) -> str:\n"
        "    reply = client.messages.create(model='c', messages=[])\n"
        "    return reply.content[0].text\n",
    )
    findings = scan_all(tmp_path)
    out = [f for f in findings if f.scanner == "llm-output"]
    assert out, "scan_all should surface llm-output findings"
    assert all(f.extra.get("family") == "llm-output-without-validation" for f in out)
