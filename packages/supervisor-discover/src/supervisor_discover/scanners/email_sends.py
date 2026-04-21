"""Detect email sends — the agent drafts + ships email from your domain.

Common attack: agent receives a support ticket with prompt injection, is told
to "email all customers announcing a promotion", sends phishing / spam / bogus
refunds. Once email leaves your SMTP, you can't recall it.

Providers: SendGrid, Mailgun, Resend, AWS SES, Postmark, SparkPost, Mailchimp
transactional, Nodemailer (SMTP), Python smtplib.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # SendGrid
    (re.compile(r"\bSendGridAPIClient\b|\bsgMail\.send\s*\("), "sendgrid", "high"),
    (re.compile(r"api\.sendgrid\.com/\S*/mail/send"), "sendgrid", "high"),
    # Mailgun
    (re.compile(r"\bmailgun[\w.]*\.messages\.create\s*\("), "mailgun", "high"),
    (re.compile(r"api\.mailgun\.net/\S*/messages"), "mailgun", "high"),
    # Resend
    (re.compile(r"\bresend\.emails\.send\s*\("), "resend", "high"),
    (re.compile(r"api\.resend\.com/\S*/emails"), "resend", "high"),
    # AWS SES
    (re.compile(r"\bses[\w.]*\.send_email\s*\(|\bSES\.Client\b"), "aws-ses", "high"),
    (re.compile(r"\bSendEmailCommand\s*\("), "aws-ses", "high"),
    # Postmark
    (re.compile(r"\bpostmark[\w.]*\.(sendEmail|emails\.send|Mail\.send)\s*\("), "postmark", "high"),
    (re.compile(r"api\.postmarkapp\.com/email"), "postmark", "high"),
    # SparkPost
    (re.compile(r"api\.sparkpost\.com/\S*/transmissions"), "sparkpost", "high"),
    # Nodemailer (SMTP, any provider)
    (re.compile(r"\bnodemailer\.createTransport\b|\btransporter\.sendMail\s*\("), "nodemailer", "high"),
    # Python smtplib
    (re.compile(r"\bsmtplib\.SMTP(_SSL)?\s*\(|\bserver\.send_message\s*\(|\bserver\.sendmail\s*\("),
     "smtplib", "high"),
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


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        for pattern, provider, severity in _SIGNATURES:
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="email-sends",
                    file=str(path),
                    line=line,
                    snippet=m.group(0)[:80],
                    suggested_action_type="tool_use",
                    confidence=severity,
                    rationale=_NARRATIVES.get(provider, _FALLBACK),
                    extra={"provider": provider},
                ))
    return findings
