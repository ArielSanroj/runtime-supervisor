"""Unit tests for the default payload extractor.

The landing-page snippet `@supervised("payment") def create_checkout(amount):`
must produce `payload['amount']` so the payment policy's `hard-cap` rule
(which reads `payload['amount']`) sees the value without forcing the dev
to write an explicit `payload=` lambda.
"""
from __future__ import annotations

from supervisor_guards.core import _make_default_extractor


def test_positional_arg_binds_by_name():
    def create_checkout(amount):
        return amount

    extract = _make_default_extractor(create_checkout)
    p = extract(1000)
    assert p["amount"] == 1000


def test_kwarg_binds_by_name():
    def create_checkout(amount, currency="USD"):
        return amount

    extract = _make_default_extractor(create_checkout)
    p = extract(amount=1000)
    assert p["amount"] == 1000
    assert p["currency"] == "USD"


def test_self_is_dropped_for_methods():
    class Cart:
        def checkout(self, amount):
            return amount

    extract = _make_default_extractor(Cart.checkout)
    cart = Cart()
    p = extract(cart, 1000)
    assert "self" not in p
    assert p["amount"] == 1000


def test_falls_back_when_signature_unavailable():
    # Builtins like `len` have no Python signature in some interpreters —
    # extractor should still return the raw args/kwargs blob, not crash.
    extract = _make_default_extractor(len)
    p = extract([1, 2, 3])
    assert "args" in p


def test_custom_extractor_overrides_default():
    # When the user passes their own `payload=`, the default is not used.
    # This test guards against a regression where _make_default_extractor
    # might be called even with a custom extractor present.
    from supervisor_guards.core import supervised

    captured = {}

    def fake_pre_check(action_type, payload, on_review):
        captured["payload"] = payload

    import supervisor_guards.core as core
    real = core._pre_check
    core._pre_check = fake_pre_check
    try:
        @supervised("payment", payload=lambda *a, **k: {"only": "this"})
        def f(amount):
            return amount

        f(999)
        assert captured["payload"] == {"only": "this"}
    finally:
        core._pre_check = real
