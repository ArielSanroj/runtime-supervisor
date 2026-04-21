"""Find payment SDK calls (Stripe / PayPal / Plaid).

Tracks Python import aliases so `import stripe as _stripe` +
`_stripe.Refund.create(...)` gets detected the same as
`stripe.Refund.create(...)`.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._imports import build_alias_map, resolve_call_name, root_module
from ._utils import python_files, safe_read, ts_js_files

# Canonical dotted paths (post-alias-resolution) that indicate money movement.
_REFUND_SIGNATURES = {
    "stripe.Refund.create", "stripe.refunds.create",
    "stripe.Refund.Refund.create",  # asymmetric stripe-python artifact
    "paypal.refunds.create", "paypalrestsdk.Refund.create",
}
_PAYMENT_SIGNATURES = {
    # one-off charges / transfers
    "stripe.Charge.create", "stripe.charges.create",
    "stripe.PaymentIntent.create", "stripe.paymentIntents.create",
    "stripe.Payout.create", "stripe.payouts.create",
    "stripe.Transfer.create", "stripe.transfers.create",
    # recurring billing — each of these moves / schedules money
    "stripe.Subscription.create", "stripe.subscriptions.create",
    "stripe.Subscription.modify", "stripe.subscriptions.update",
    "stripe.Subscription.cancel", "stripe.subscriptions.cancel",
    "stripe.SubscriptionItem.create", "stripe.SubscriptionItem.update",
    # hosted checkout — initiates a payment flow
    "stripe.checkout.Session.create",
    # invoice + customer billing state
    "stripe.Invoice.create", "stripe.invoices.create",
    "stripe.Invoice.pay", "stripe.invoices.pay",
    # other vendors
    "paypal.payouts.create", "paypal.orders.create",
    "paypalrestsdk.Payout.create", "paypalrestsdk.Payment.create",
    "plaid.Transfer.create", "plaid.transfer.create",
}
_PAYMENT_ROOTS = {"stripe", "paypal", "paypalrestsdk", "plaid"}


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        aliases = build_alias_map(tree)
        if not any(root_module(v) in _PAYMENT_ROOTS for v in aliases.values()):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = resolve_call_name(node, aliases)
            if dotted in _REFUND_SIGNATURES:
                findings.append(Finding(
                    scanner="payment-calls", file=str(path), line=node.lineno,
                    snippet=f"{dotted}(...)",
                    suggested_action_type="refund",
                    confidence="high",
                    rationale=f"Money movement via `{dotted}`. Must be gated by a refund policy before execution.",
                    extra={"method": dotted, "vendor": root_module(dotted)},
                ))
            elif dotted in _PAYMENT_SIGNATURES:
                findings.append(Finding(
                    scanner="payment-calls", file=str(path), line=node.lineno,
                    snippet=f"{dotted}(...)",
                    suggested_action_type="payment",
                    confidence="high",
                    rationale=f"Outgoing payment via `{dotted}`. Must be gated by a payment policy with approval chain.",
                    extra={"method": dotted, "vendor": root_module(dotted)},
                ))
    return findings


_TS_REFUND_RE = re.compile(
    r"""\b(?:stripe|Stripe)\.refunds\.create\s*\(|\bpaypal\.refunds\.create\s*\("""
)
_TS_PAYMENT_RE = re.compile(
    r"""\b(?:stripe|Stripe)\.(?:charges|paymentIntents|payouts|transfers)\.create\s*\("""
    r"""|\bpaypal\.(?:payouts|orders)\.create\s*\("""
    r"""|\bplaid\.transfer\.create\s*\("""
)


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        for m in _TS_REFUND_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            snippet = m.group(0).rstrip("(")
            findings.append(Finding(
                scanner="payment-calls", file=str(path), line=line, snippet=snippet,
                suggested_action_type="refund", confidence="high",
                rationale=f"Money movement via `{snippet}`. Must be gated by a refund policy.",
                extra={"method": snippet, "vendor": snippet.split(".")[0].lower()},
            ))
        for m in _TS_PAYMENT_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            snippet = m.group(0).rstrip("(")
            findings.append(Finding(
                scanner="payment-calls", file=str(path), line=line, snippet=snippet,
                suggested_action_type="payment", confidence="high",
                rationale=f"Outgoing payment via `{snippet}`. Must be gated by a payment policy.",
                extra={"method": snippet, "vendor": snippet.split(".")[0].lower()},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
