"""Find payment SDK calls (Stripe / PayPal / Plaid)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, ts_js_files

_REFUND_METHODS = {
    "stripe.Refund.create", "stripe.refunds.create",
    "Stripe.refunds.create",  # TS stripe-node variant
    "paypal.refunds.create",
}
_PAYMENT_METHODS = {
    "stripe.Charge.create", "stripe.charges.create",
    "stripe.PaymentIntent.create", "stripe.paymentIntents.create",
    "stripe.Payout.create", "stripe.payouts.create",
    "stripe.Transfer.create", "stripe.transfers.create",
    "paypal.payouts.create", "paypal.orders.create",
    "plaid.transfer.create", "plaid.Transfer.create",
}


def _py_call_name(node: ast.Call) -> str:
    fn = node.func
    parts: list[str] = []
    while isinstance(fn, ast.Attribute):
        parts.append(fn.attr)
        fn = fn.value
    if isinstance(fn, ast.Name):
        parts.append(fn.id)
    return ".".join(reversed(parts))


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        try:
            tree = ast.parse(path.read_text(errors="ignore"))
        except (SyntaxError, ValueError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _py_call_name(node)
            if name in _REFUND_METHODS:
                findings.append(Finding(
                    scanner="payment-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=f"{name}(...)",
                    suggested_action_type="refund",
                    confidence="high",
                    rationale=f"Money movement via `{name}`. Must be gated by a refund policy before execution.",
                    extra={"method": name, "vendor": name.split(".")[0]},
                ))
            elif name in _PAYMENT_METHODS:
                findings.append(Finding(
                    scanner="payment-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=f"{name}(...)",
                    suggested_action_type="payment",
                    confidence="high",
                    rationale=f"Outgoing payment via `{name}`. Must be gated by a payment policy with approval chain.",
                    extra={"method": name, "vendor": name.split(".")[0]},
                ))
    return findings


_TS_REFUND_RE = re.compile(
    r"""\b(stripe|Stripe)\.refunds\.create\s*\(|\bpaypal\.refunds\.create\s*\("""
)
_TS_PAYMENT_RE = re.compile(
    r"""\b(stripe|Stripe)\.(charges|paymentIntents|payouts|transfers)\.create\s*\("""
    r"""|\bpaypal\.(payouts|orders)\.create\s*\("""
    r"""|\bplaid\.transfer\.create\s*\("""
)


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = path.read_text(errors="ignore")
        for m in _TS_REFUND_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            snippet = m.group(0).rstrip("(")
            findings.append(Finding(
                scanner="payment-calls",
                file=str(path),
                line=line,
                snippet=snippet,
                suggested_action_type="refund",
                confidence="high",
                rationale=f"Money movement via `{snippet}`. Must be gated by a refund policy.",
                extra={"method": snippet, "vendor": snippet.split(".")[0].lower()},
            ))
        for m in _TS_PAYMENT_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            snippet = m.group(0).rstrip("(")
            findings.append(Finding(
                scanner="payment-calls",
                file=str(path),
                line=line,
                snippet=snippet,
                suggested_action_type="payment",
                confidence="high",
                rationale=f"Outgoing payment via `{snippet}`. Must be gated by a payment policy.",
                extra={"method": snippet, "vendor": snippet.split(".")[0].lower()},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
