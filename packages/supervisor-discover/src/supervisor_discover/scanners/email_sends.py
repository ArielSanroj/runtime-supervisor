"""Detect email sends — the agent drafts + ships email from your domain.

Common attack: agent receives a support ticket with prompt injection, is told
to "email all customers announcing a promotion", sends phishing / spam / bogus
refunds. Once email leaves your SMTP, you can't recall it.

Providers: SendGrid, Mailgun, Resend, AWS SES, Postmark, SparkPost, Mailchimp
transactional, Nodemailer (SMTP), Python smtplib.

Python detection: AST-based — iterates `ast.Call` and matches the resolved
dotted name against `_PY_CALL_TARGETS`. Immune to matches inside comments,
docstrings, f-strings, or plain string literals. URL patterns still use regex
because they're useful for both languages and URLs rarely appear in prose.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import iter_python_calls, match_dotted_call, python_files, safe_read, ts_js_files


# Python SDK call signatures — matched via AST. Key: dotted-name or suffix;
# value: (provider, confidence).
_PY_CALL_TARGETS: dict[str, tuple[str, str]] = {
    # SendGrid — fully-qualified (avoid cross-vendor collisions).
    "sgMail.send":              ("sendgrid", "high"),
    "SendGridAPIClient":        ("sendgrid", "high"),
    # Mailgun — the vendor prefix is required so we don't collide with
    # `anthropic.messages.create` or `twilio.messages.create`.
    "mailgun.messages.create":  ("mailgun", "high"),
    "mg.messages.create":       ("mailgun", "high"),
    # Resend
    "resend.emails.send":       ("resend", "high"),
    # AWS SES
    "ses.send_email":           ("aws-ses", "high"),
    "SendEmailCommand":         ("aws-ses", "high"),
    # Postmark
    "postmark.sendEmail":       ("postmark", "high"),
    "postmark.emails.send":     ("postmark", "high"),
    "postmark.Mail.send":       ("postmark", "high"),
    # Python smtplib
    "smtplib.SMTP":             ("smtplib", "high"),
    "smtplib.SMTP_SSL":         ("smtplib", "high"),
    "server.send_message":      ("smtplib", "high"),
    "server.sendmail":          ("smtplib", "high"),
}

# URL regex patterns — language-agnostic, useful for JS too. These rarely
# appear verbatim in prose, so FP risk is low.
_URL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"api\.sendgrid\.com/\S*/mail/send"), "sendgrid", "high"),
    (re.compile(r"api\.mailgun\.net/\S*/messages"), "mailgun", "high"),
    (re.compile(r"api\.resend\.com/\S*/emails"), "resend", "high"),
    (re.compile(r"api\.postmarkapp\.com/email"), "postmark", "high"),
    (re.compile(r"api\.sparkpost\.com/\S*/transmissions"), "sparkpost", "high"),
]

# JS/TS SDK patterns — no cheap AST, stick with regex anchored on vendor ids.
_JS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bSendGridAPIClient\b|\bsgMail\.send\s*\("), "sendgrid", "high"),
    (re.compile(r"\bmailgun[\w.]*\.messages\.create\s*\("), "mailgun", "high"),
    (re.compile(r"\bresend\.emails\.send\s*\("), "resend", "high"),
    (re.compile(r"\bSendEmailCommand\s*\("), "aws-ses", "high"),
    (re.compile(r"\bpostmark[\w.]*\.(sendEmail|emails\.send|Mail\.send)\s*\("), "postmark", "high"),
    (re.compile(r"\bnodemailer\.createTransport\b|\btransporter\.sendMail\s*\("), "nodemailer", "high"),
]


_NARRATIVES: dict[str, str] = {
    "sendgrid": (
        "SendGrid email. Sent from your verified domain + DKIM. A compromised agent can "
        "email your entire customer list; inbox providers trust your sender reputation until "
        "they don't, and recovering it is slow."
    ),
    "mailgun": (
        "Mailgun email. Same risk profile as SendGrid — domain-authenticated, high-trust. "
        "A prompt-injection can trigger mass phishing from your actual domain."
    ),
    "resend": (
        "Resend email. Dev-friendly API, often used for transactional email. Compromised → "
        "password reset emails to attacker-chosen addresses, confirmation spam, scam campaigns."
    ),
    "aws-ses": (
        "AWS SES email. Raw SMTP-shape API, often used for bulk sends. A prompt-injected "
        "agent can burn your SES reputation fast; getting unblocked requires AWS support ticket."
    ),
    "postmark": (
        "Postmark email. Transactional-focused, so compromised agent can fake order "
        "confirmations, shipping notifications, invoices."
    ),
    "sparkpost": (
        "SparkPost email. Bulk-capable — scales a phishing campaign to millions."
    ),
    "nodemailer": (
        "Nodemailer via SMTP. Whatever SMTP account this uses becomes a phishing server "
        "the moment a prompt-injection succeeds. Check the SMTP account's reputation."
    ),
    "smtplib": (
        "Python smtplib direct SMTP. Same as nodemailer — the SMTP account behind it becomes "
        "the phishing server."
    ),
}

_FALLBACK = (
    "Email send — agent emits mail from your domain. Prompt-injection → mass phishing, data "
    "leak, spam filter reputation damage."
)


def _scan_python(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    source_lines = text.splitlines()
    for call in iter_python_calls(text):
        hit = match_dotted_call(call, _PY_CALL_TARGETS)
        if hit is None:
            continue
        _, (provider, severity) = hit
        line = call.lineno
        snippet = source_lines[line - 1].strip()[:80] if 0 <= line - 1 < len(source_lines) else provider
        out.append(Finding(
            scanner="email-sends",
            file=str(path),
            line=line,
            snippet=snippet,
            suggested_action_type="tool_use",
            confidence=severity,
            rationale=_NARRATIVES.get(provider, _FALLBACK),
            extra={"provider": provider},
        ))
    # URL string matches — still regex (low FP risk)
    for pattern, provider, severity in _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(Finding(
                scanner="email-sends",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80],
                suggested_action_type="tool_use",
                confidence=severity,
                rationale=_NARRATIVES.get(provider, _FALLBACK),
                extra={"provider": provider},
            ))
    return out


def _scan_js(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for pattern, provider, severity in _JS_PATTERNS + _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(Finding(
                scanner="email-sends",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80],
                suggested_action_type="tool_use",
                confidence=severity,
                rationale=_NARRATIVES.get(provider, _FALLBACK),
                extra={"provider": provider},
            ))
    return out


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_python(path, text))
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_js(path, text))
    return findings
