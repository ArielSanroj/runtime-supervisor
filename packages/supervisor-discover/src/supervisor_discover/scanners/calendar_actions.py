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
from ._utils import python_files, safe_read, ts_js_files

_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # Google Calendar — both client library and raw HTTP
    (re.compile(r"\bcalendar[\w.]*\.events\.(insert|update|patch|delete|quickAdd)\s*\("), "google", "high"),
    (re.compile(r"\bservice\.events\(\)\.(insert|update|patch|delete)\s*\("), "google", "high"),
    (re.compile(r"www\.googleapis\.com/calendar/v3/calendars/\S*/events"), "google", "high"),
    # Microsoft Graph calendar
    (re.compile(r"graph\.microsoft\.com/\S*/events\b"), "outlook", "high"),
    (re.compile(r"\bcalendar\.events\(\)\.post\s*\("), "outlook", "high"),
    # Cal.com
    (re.compile(r"api\.cal\.com/\S*/bookings"), "cal.com", "high"),
    (re.compile(r"\bcal[\w.]*\.(bookings|events)\.create\s*\("), "cal.com", "high"),
    # Calendly
    (re.compile(r"api\.calendly\.com/scheduled_events"), "calendly", "medium"),
    # Zoom meetings (often paired with calendar)
    (re.compile(r"\bzoom[\w.]*\.meetings\.create\s*\("), "zoom", "medium"),
    (re.compile(r"api\.zoom\.us/v2/users/\S*/meetings"), "zoom", "medium"),
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
        for pattern, provider, severity in _SIGNATURES:
            for m in pattern.finditer(text):
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
