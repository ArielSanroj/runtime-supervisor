"""Tests for gate_coverage — detecting call-sites already wrapped by
@supervised / guarded(...).

The point is to stop telling users to 'do this now: wrap stripe' when
they already wrapped stripe on a previous PR. False positives here just
mean we don't recommend re-wrapping (annoying); false negatives gaslight
the user.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_discover.findings import Finding
from supervisor_discover.gate_coverage import (
    annotate_findings,
    already_gated,
)


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_decorator_supervised_marks_finding_as_gated(tmp_path: Path):
    src = _write(tmp_path, "service.py", """
from supervisor_guards import supervised

class Service:
    @supervised("payment")
    def charge(self, amount):
        return stripe.Charge.create(amount=amount)
""")
    f = Finding(
        scanner="payment-calls", file=str(src), line=6,
        snippet="stripe.Charge.create(", suggested_action_type="payment",
        confidence="high", rationale="...", extra={},
    )
    annotate_findings([f])
    assert already_gated(f)
    assert f.extra.get("gated_by") == "@supervised"


def test_guarded_call_marks_inner_function_as_gated(tmp_path: Path):
    """The supervincent pattern — `guarded("payment", payload, fn, *args)`
    where `fn` is the function that contains the actual stripe call."""
    src = _write(tmp_path, "payments.py", """
from supervisor_guards import guarded

def create_checkout(body, price_id, kw, user):
    payload = {"action": "checkout"}
    return guarded("payment", payload, _do_stripe_checkout, body, price_id)


def _do_stripe_checkout(body, price_id):
    return stripe.checkout.Session.create(price=price_id)
""")
    f = Finding(
        scanner="payment-calls", file=str(src), line=10,
        snippet="stripe.checkout.Session.create(",
        suggested_action_type="payment", confidence="high",
        rationale="...", extra={},
    )
    annotate_findings([f])
    assert already_gated(f)
    assert "guarded" in (f.extra.get("gated_by") or "")


def test_finding_outside_gated_function_remains_unmarked(tmp_path: Path):
    """A gate on `charge` should NOT mark a stripe call in `refund` as gated."""
    src = _write(tmp_path, "service.py", """
from supervisor_guards import supervised

class Service:
    @supervised("payment")
    def charge(self, amount):
        return stripe.Charge.create(amount=amount)

    def refund(self, charge_id):
        return stripe.Refund.create(charge=charge_id)
""")
    f = Finding(
        scanner="payment-calls", file=str(src), line=10,
        snippet="stripe.Refund.create(", suggested_action_type="payment",
        confidence="high", rationale="...", extra={},
    )
    annotate_findings([f])
    assert not already_gated(f)


def test_unparseable_file_gracefully_passes_through(tmp_path: Path):
    src = _write(tmp_path, "broken.py", "def x(:\n    pass")
    f = Finding(
        scanner="fs-shell", file=str(src), line=1,
        snippet="subprocess.run(", suggested_action_type="tool_use",
        confidence="high", rationale="...", extra={},
    )
    annotate_findings([f])
    assert not already_gated(f)
    assert f.extra.get("already_gated") is False


def test_non_python_file_passes_through(tmp_path: Path):
    src = _write(tmp_path, "service.ts", "function charge() {}")
    f = Finding(
        scanner="payment-calls", file=str(src), line=1,
        snippet="stripe.Charge.create(", suggested_action_type="payment",
        confidence="high", rationale="...", extra={},
    )
    annotate_findings([f])
    assert not already_gated(f)


def test_annotate_is_idempotent(tmp_path: Path):
    src = _write(tmp_path, "s.py", """
from supervisor_guards import supervised

@supervised("tool_use")
def do_thing():
    subprocess.run(["echo", "hi"])
""")
    f = Finding(
        scanner="fs-shell", file=str(src), line=5,
        snippet="subprocess.run(", suggested_action_type="tool_use",
        confidence="high", rationale="...", extra={},
    )
    annotate_findings([f])
    label_first = f.extra.get("gated_by")
    annotate_findings([f])
    assert f.extra.get("gated_by") == label_first
