"""Tests for the AST-derived stub payload extractor.

Without these helpers, every agent-class stub in `stubs/py/` shipped
with `lambda *args, **kwargs: {"raw_args": ..., "raw_kwargs": ...}` —
which never matches a real policy `when:` clause and forces the dev
to rewrite the lambda before it works. With these helpers, the stub
arrives with the dispatcher's actual param names so the dev only has
to edit the field-to-policy mapping.
"""
from __future__ import annotations

import ast
from pathlib import Path

from supervisor_discover.wrap_signature import (
    DispatcherSignature,
    extract_dispatcher_signature,
    render_lambda_args,
    render_payload_body_from_signature,
)


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


# ─── extract_dispatcher_signature ─────────────────────────────────


def test_picks_method_with_decision_branching(tmp_path: Path):
    src = _write(tmp_path, "agent.py", """
class ElectoralAgent:
    def handle(self, x): return self._dispatch(x)
    def _dispatch(self, decision):
        action = decision.action
        if action == "create": return 1
        if action == "delete": return 2
        return None
""")
    sig = extract_dispatcher_signature(str(src), "ElectoralAgent")
    assert sig is not None
    assert sig.method_name == "_dispatch"
    assert sig.param_names == ("self", "decision")


def test_picks_named_method_when_no_branching(tmp_path: Path):
    src = _write(tmp_path, "agent.py", """
class PlainAgent:
    def helper(self, x): return x
    def handle(self, payload): return self.helper(payload)
""")
    sig = extract_dispatcher_signature(str(src), "PlainAgent")
    assert sig is not None
    assert sig.method_name == "handle"


def test_returns_none_for_missing_class(tmp_path: Path):
    src = _write(tmp_path, "agent.py", "class OtherAgent: pass\n")
    assert extract_dispatcher_signature(str(src), "MissingAgent") is None


def test_returns_none_for_non_python(tmp_path: Path):
    src = _write(tmp_path, "agent.ts", "class Foo { handle(x) {} }\n")
    assert extract_dispatcher_signature(str(src), "Foo") is None


def test_returns_none_for_class_with_no_methods(tmp_path: Path):
    src = _write(tmp_path, "agent.py", """
class EmptyAgent:
    pass
""")
    assert extract_dispatcher_signature(str(src), "EmptyAgent") is None


def test_strips_tool_prefix_from_label(tmp_path: Path):
    """Wrap target labels for tool-registration findings carry a
    `"tool: <name>"` prefix. The extractor should strip it before
    looking up the class name."""
    src = _write(tmp_path, "agent.py", """
class TaskAgent:
    def handle(self, task): return None
""")
    sig = extract_dispatcher_signature(str(src), "tool: TaskAgent")
    assert sig is not None
    assert sig.class_name == "TaskAgent"


def test_parallel_methods_take_priority(tmp_path: Path):
    """When the class has parallel dispatch methods, the picker returns
    the first one in the list — the renderer instructs the dev to
    repeat for the others."""
    src = _write(tmp_path, "agent.py", """
class AlertDispatcher:
    async def dispatch_sla_alert(self, alert): return None
    async def dispatch_anomaly_alert(self, alert): return None
    async def dispatch_deadline_alert(self, alert): return None
    def handle(self, x): return None
""")
    sig = extract_dispatcher_signature(
        str(src), "AlertDispatcher",
        parallel_methods=("dispatch_anomaly_alert", "dispatch_sla_alert"),
    )
    assert sig is not None
    # First in the parallel list wins, even though the class also has handle().
    assert sig.method_name == "dispatch_anomaly_alert"


def test_async_method_marked_async(tmp_path: Path):
    src = _write(tmp_path, "agent.py", """
class AsyncAgent:
    async def run(self, payload): return None
""")
    sig = extract_dispatcher_signature(str(src), "AsyncAgent")
    assert sig is not None
    assert sig.is_async is True


# ─── render_lambda_args ────────────────────────────────────────────


def _make_sig(*params: str, has_kwarg: bool = False) -> DispatcherSignature:
    if has_kwarg:
        params = (*params, "**kw")
    return DispatcherSignature(
        class_name="X", method_name="m", is_async=False,
        line=1, arg_signature="", param_names=params, parallel_methods=(),
    )


def test_lambda_args_strip_annotations_and_add_defaults():
    """The dispatcher signature `(self, year: Optional[int]=None, month=None)`
    must render as `self=None, year=None, month=None, **kw` — annotations
    are illegal in lambdas, and adding `=None` plus `**kw` keeps the
    lambda invocable from any call shape."""
    sig = _make_sig("self", "year", "month")
    args = render_lambda_args(sig)
    assert "self=None" in args
    assert "year=None" in args
    assert "month=None" in args
    assert "**kw" in args
    # Smoke test: the lambda must be valid Python.
    code = f"lambda {args}: 1"
    ast.parse(code)


def test_lambda_args_preserves_existing_kwarg():
    """When the dispatcher already has `**kw`, don't double up."""
    sig = _make_sig("self", "task", has_kwarg=True)
    args = render_lambda_args(sig)
    # Only one **kw, regardless.
    assert args.count("**kw") == 1


def test_lambda_args_handles_only_self():
    sig = _make_sig("self")
    args = render_lambda_args(sig)
    code = f"lambda {args}: 1"
    ast.parse(code)


# ─── render_payload_body_from_signature ────────────────────────────


def test_payload_body_lists_visible_params_only():
    """`self`, `*args`, `**kwargs` should NOT appear in the payload body
    even when they're in the lambda's arg list — they aren't useful as
    policy fields."""
    sig = _make_sig("self", "year", "month", "*args", has_kwarg=True)
    body = render_payload_body_from_signature(sig)
    assert '"year": year' in body
    assert '"month": month' in body
    assert '"self":' not in body
    assert '"*args":' not in body


def test_payload_body_empty_when_no_visible_params():
    """A method with only `(self)` has no meaningful payload — the
    helper returns "" so the caller can fall back to the generic body."""
    sig = _make_sig("self")
    body = render_payload_body_from_signature(sig)
    assert body == ""


def test_payload_body_is_valid_python_when_embedded():
    sig = _make_sig("self", "decision", "context")
    body = render_payload_body_from_signature(sig)
    args = render_lambda_args(sig)
    code = f"f = lambda {args}: {{\n{body}\n}}\n"
    ast.parse(code)
