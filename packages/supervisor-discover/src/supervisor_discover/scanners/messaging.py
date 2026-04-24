"""Detect messaging actions — the agent posts to Slack / Discord / Teams / SMS / WhatsApp.

Scope: anything that ends with a human reading a message that a human did NOT
write. Common attack: prompt-injection convinces agent to post a phishing link,
DM sensitive info, impersonate someone, or spam a channel.

Providers: Slack (chat_postMessage, webhooks), Discord (webhook, bot send),
Microsoft Teams (webhook, Graph API), Telegram (sendMessage), Twilio SMS,
WhatsApp Business API.

Python: AST-based on dotted call names. JS/TS + URL patterns: regex.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import iter_python_calls, match_dotted_call, python_files, safe_read, ts_js_files

# Python SDK targets — suffix-matched dotted names.
_PY_CALL_TARGETS: dict[str, tuple[str, str, str]] = {
    # (provider, label, confidence). Use fully-qualified dotted names to
    # avoid collisions — `messages.create` also matches Anthropic SDK.
    "slack.chat_postMessage":   ("slack", "post to channel/DM", "high"),
    "web_client.chat_postMessage": ("slack", "post to channel/DM", "high"),
    "client.chat_postMessage":  ("slack", "post to channel/DM", "high"),
    "slack.chat.postMessage":   ("slack", "post to channel/DM", "high"),
    "web.chat.postMessage":     ("slack", "post to channel/DM", "high"),
    "bot.send_message":         ("telegram", "bot send", "high"),
    "telegram.send_message":    ("telegram", "bot send", "high"),
    "twilio.messages.create":   ("twilio", "SMS or WhatsApp", "high"),
}

# URL regex — language-agnostic. URLs are very unlikely to appear in prose.
_URL_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"hooks\.slack\.com/services/\S+"), "slack", "webhook post", "high"),
    (re.compile(r"discord\.com/api/webhooks/\S+"), "discord", "webhook post", "high"),
    (re.compile(r"outlook\.office\.com/webhook/\S+"), "teams", "webhook post", "high"),
    (re.compile(r"graph\.microsoft\.com/\S*(?:chats|channels)/\S*/messages"),
     "teams", "Graph API send", "high"),
    (re.compile(r"api\.telegram\.org/bot\S+/sendMessage"), "telegram", "bot message", "high"),
    (re.compile(r"api\.twilio\.com/\S*/Messages"), "twilio", "raw Twilio SMS API", "high"),
    (re.compile(r"graph\.facebook\.com/\S*/messages"), "whatsapp",
     "WhatsApp Business send", "high"),
]

# JS/TS SDK patterns — require `(` suffix for call syntax.
_JS_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\b(?:slack|web_client|client)\.chat_postMessage\s*\(", re.I),
     "slack", "post to channel/DM", "high"),
    (re.compile(r"\b(?:slack|web)\.chat\.postMessage\s*\("),
     "slack", "post to channel/DM", "high"),
    (re.compile(r"\bWebClient\s*\([^)]*\)\.[\w.]*post"),
     "slack", "slack SDK call", "medium"),
    (re.compile(r"\bWebhookClient\s*\("), "discord", "discord.js webhook", "high"),
    (re.compile(r"\b(?:channel|thread|user)\.send\s*\("),
     "discord", "bot send message", "medium"),
    (re.compile(r"\btwilio[\w.]*\.messages\.create\s*\("),
     "twilio", "SMS or WhatsApp", "high"),
]


_NARRATIVES: dict[str, str] = {
    "slack": (
        "Post to Slack — channel or DM. A prompt-injected agent can spam your workspace, "
        "DM phishing links to every employee, or post internal secrets to #general."
    ),
    "discord": (
        "Post to Discord via webhook or bot. Gate with channel-ID allowlist; a compromised "
        "agent floods any channel it has access to."
    ),
    "teams": (
        "Post to Microsoft Teams via webhook or Graph API. Internal messages look trusted, "
        "phishing links inside them have high click-through."
    ),
    "telegram": (
        "Telegram bot send. If the bot is in group chats with customers or employees, "
        "a compromised agent can DM them with phishing or disinformation."
    ),
    "twilio": (
        "Twilio SMS or WhatsApp. A prompt-injected agent becomes a texting spammer — sends "
        "from your verified number, so recipients trust it. High fraud potential."
    ),
    "whatsapp": (
        "WhatsApp Business via Meta Graph. Messages come from your verified business number. "
        "Can scam your customer base on their most trusted channel."
    ),
}

_FALLBACK = (
    "Messaging action — agent sends a message a human reads. Prompt-injection can turn this "
    "into phishing, impersonation, or data leak."
)


def _emit(path: Path, line: int, snippet: str, provider: str, label: str,
          severity: str) -> Finding:
    return Finding(
        scanner="messaging",
        file=str(path),
        line=line,
        snippet=snippet[:80],
        suggested_action_type="tool_use",
        confidence=severity,
        rationale=_NARRATIVES.get(provider, _FALLBACK),
        extra={"provider": provider, "label": label},
    )


def _scan_python(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    source_lines = text.splitlines()
    for call in iter_python_calls(text):
        hit = match_dotted_call(call, _PY_CALL_TARGETS)
        if hit is None:
            continue
        _, (provider, label, severity) = hit
        snippet = source_lines[call.lineno - 1].strip() if 0 <= call.lineno - 1 < len(source_lines) else provider
        out.append(_emit(path, call.lineno, snippet, provider, label, severity))
    for pattern, provider, label, severity in _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(_emit(path, line, m.group(0), provider, label, severity))
    return out


def _scan_js(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for pattern, provider, label, severity in _JS_PATTERNS + _URL_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            out.append(_emit(path, line, m.group(0), provider, label, severity))
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
