"""Detect calendar/meeting actions — the agent books time on someone's calendar.

Common scenarios: sales agent schedules a demo, assistant books a doctor
appointment, voice agent reserves a conference room. Impact: scheduled
events, invites sent, conflicts with real humans' time. Prompt injection
could create fake events or spam invites to hundreds of contacts.

Providers: Google Calendar API, Microsoft Graph (calendar), Cal.com,
Calendly (typically inbound, but outbound booking exists via API).
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import detect_http_verb_near, python_files, safe_read, ts_js_files

# Each signature carries:
#   regex         — the pattern that matches a URL or SDK method
#   provider      — vendor key (lookup into _NARRATIVES)
#   confidence    — high / medium
#   url_only      — True when the regex matches a URL string with no verb baked
#                   in (e.g. `…/calendars/{id}/events` matches GET, POST, PUT,
#                   DELETE alike). Those need verb sniffing in the surrounding
#                   text to avoid flagging GETs as "mutations". False for SDK
#                   calls like `events.insert(…)` where the verb is in the name.
_SIGNATURES: list[tuple[re.Pattern, str, str, bool]] = [
    # Google Calendar — both client library and raw HTTP
    (re.compile(r"\bcalendar[\w.]*\.events\.(insert|update|patch|delete|quickAdd)\s*\("), "google", "high", False),
    (re.compile(r"\bservice\.events\(\)\.(insert|update|patch|delete)\s*\("), "google", "high", False),
    (re.compile(r"www\.googleapis\.com/calendar/v3/calendars/\S*/events"), "google", "high", True),
    # Microsoft Graph calendar
    (re.compile(r"graph\.microsoft\.com/\S*/events\b"), "outlook", "high", True),
    (re.compile(r"\bcalendar\.events\(\)\.post\s*\("), "outlook", "high", False),
    # Cal.com
    (re.compile(r"api\.cal\.com/\S*/bookings"), "cal.com", "high", True),
    (re.compile(r"\bcal[\w.]*\.(bookings|events)\.create\s*\("), "cal.com", "high", False),
    # Calendly
    (re.compile(r"api\.calendly\.com/scheduled_events"), "calendly", "medium", True),
    # Zoom meetings (often paired with calendar)
    (re.compile(r"\bzoom[\w.]*\.meetings\.create\s*\("), "zoom", "medium", False),
    (re.compile(r"api\.zoom\.us/v2/users/\S*/meetings"), "zoom", "medium", True),
]

_NARRATIVES: dict[str, str] = {
    "google": (
        "Google Calendar events API. The agent can insert, update, or delete events on "
        "any calendar the OAuth token has access to — including a user's personal calendar "
        "if they granted full scope. Risks: fake medical appointments (imagine a phishing "
        "event titled 'Appointment with Dr. X — tap link'), ghost-invites to thousands of "
        "contacts, silent meeting deletions that make legitimate events disappear."
    ),
    "outlook": (
        "Microsoft Graph calendar. Same shape as Google — an agent with event-write "
        "permission can inject phishing events into corporate calendars. Event descriptions "
        "render as clickable links in mobile notifications."
    ),
    "cal.com": (
        "Cal.com booking. A compromised agent can create bookings on anyone's Cal.com "
        "account tied to this OAuth/API key, spam calendars with back-to-back fake meetings, "
        "or trigger email invites to attendees of the attacker's choosing."
    ),
    "calendly": (
        "Calendly scheduled-events API (typically read-mostly, but write endpoints exist). "
        "Lower direct write risk; most exposure is unintended data access to booking details."
    ),
    "zoom": (
        "Zoom meeting creation. A compromised agent can spin up meetings, post the links "
        "in phishing messages, or chain with voice-clone providers to host spoofed meetings."
    ),
}

_FALLBACK = (
    "Calendar / meeting action — agent books time on real people's calendars. Prompt-"
    "injection can create fake appointments, spam invites, or delete legitimate events."
)


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        for pattern, provider, severity, url_only in _SIGNATURES:
            for m in pattern.finditer(text):
                # URL-only patterns match GET/POST/PUT/DELETE alike. Sniff the
                # surrounding code for the verb; skip reads (a GET against an
                # events list is not a calendar mutation, it's a query).
                if url_only:
                    verb = detect_http_verb_near(text, m.start())
                    if verb == "READ":
                        continue
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="calendar-actions",
                    file=str(path),
                    line=line,
                    snippet=m.group(0)[:80],
                    suggested_action_type="tool_use",
                    confidence=severity,
                    rationale=_NARRATIVES.get(provider, _FALLBACK),
                    extra={"provider": provider},
                ))
    return findings
