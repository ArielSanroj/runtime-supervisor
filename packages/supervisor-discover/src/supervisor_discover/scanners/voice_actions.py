"""Detect voice / telephony actions — the agent can make phone calls.

Scope: outbound calls, voice synthesis, call transfers. These are real-world
high-impact actions (the agent dials a human, a clone-voice speaks, costs
money per-minute, can be weaponized for social-engineering / vishing).

Providers: Twilio (Voice), Retell, Vapi, Bland, Daily, Agora, Plivo,
Vonage, ElevenLabs (text-to-speech + voice cloning).

Python: AST-based dotted-name matching. JS/TS + URL patterns: regex.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import iter_python_calls, match_dotted_call, python_files, safe_read, ts_js_files


_PY_CALL_TARGETS: dict[str, tuple[str, str, str]] = {
    # (provider, label, confidence). Always vendor-qualified to avoid
    # cross-vendor collisions like `messages.create`.
    "twilio.calls.create":    ("twilio", "outbound phone call", "high"),
    "retell.call":            ("retell", "AI voice agent call", "high"),
    "retell.phone_call":      ("retell", "AI voice agent call", "high"),
    "retell.createPhoneCall": ("retell", "AI voice agent call", "high"),
    "vapi.calls.create":      ("vapi", "AI voice agent call", "high"),
    "bland.calls.create":     ("bland", "AI voice agent call", "high"),
    "plivo.calls.create":     ("plivo", "outbound phone call", "high"),
    "vonage.calls.create":    ("vonage", "outbound phone call", "high"),
    "elevenlabs.generate":    ("elevenlabs", "voice synthesis (possible clone)", "high"),
    "elevenlabs.text_to_speech": ("elevenlabs", "voice synthesis (possible clone)", "high"),
    "elevenlabs.textToSpeech": ("elevenlabs", "voice synthesis (possible clone)", "high"),
    "client.voices.add":      ("elevenlabs", "voice cloning", "high"),
    "client.voices.clone":    ("elevenlabs", "voice cloning", "high"),
    "xi.voices.add":          ("elevenlabs", "voice cloning", "high"),
    "xi.voices.clone":        ("elevenlabs", "voice cloning", "high"),
}

# URL regex patterns — language-agnostic.
_URL_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"api\.twilio\.com/\S*(?:Calls|Conferences)"),
     "twilio", "raw Twilio voice API call", "high"),
    (re.compile(r"api\.elevenlabs\.io/\S*(?:text-to-speech|voices)"),
     "elevenlabs", "raw ElevenLabs API call", "high"),
    (re.compile(r"api\.retellai\.com/\S*"), "retell", "raw Retell API call", "high"),
    (re.compile(r"api\.vapi\.ai/\S*"), "vapi", "raw Vapi API call", "high"),
]

# JS/TS SDK patterns.
_JS_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\btwilio[\w.]*\.calls\.create\s*\("),
     "twilio", "outbound phone call", "high"),
    (re.compile(r"\btwilio[\w.]*\.conferences\b"),
     "twilio", "conference bridge", "medium"),
    (re.compile(r"\bretell[\w.]*\.(call|phone_call|createPhoneCall)\b"),
     "retell", "AI voice agent call", "high"),
    (re.compile(r"\bvapi[\w.]*\.calls\.create\s*\("),
     "vapi", "AI voice agent call", "high"),
    (re.compile(r"\bbland[\w.]*\.calls\.create\s*\("),
     "bland", "AI voice agent call", "high"),
    (re.compile(r"\bplivo[\w.]*\.calls\.create\s*\("),
     "plivo", "outbound phone call", "high"),
    (re.compile(r"\bvonage[\w.]*\.calls\.create\s*\("),
     "vonage", "outbound phone call", "high"),
    (re.compile(r"\bdaily[\w.]*\.(rooms|createRoom)\b"),
     "daily", "video room creation", "medium"),
    (re.compile(r"\belevenlabs[\w.]*\.(generate|text_to_speech|textToSpeech|tts)\b", re.I),
     "elevenlabs", "voice synthesis (possible clone)", "high"),
    (re.compile(r"\b(?:client|xi)\.voices\.(add|clone)\b", re.I),
     "elevenlabs", "voice cloning", "high"),
]


_NARRATIVES: dict[str, str] = {
    "twilio": (
        "Outbound phone call via Twilio. A prompt-injected agent can dial any number on "
        "earth — including premium-rate lines ($/min bill shock) or targets of a phishing "
        "campaign. Combined with voice synth (ElevenLabs), it's a social-engineering weapon."
    ),
    "retell": (
        "AI voice agent (Retell) — an LLM-driven phone call. Combines reasoning + voice "
        "synthesis + dialing in one API call, so one compromised prompt = autonomous "
        "voice-phishing campaign."
    ),
    "vapi": (
        "Vapi AI voice agent. LLM + TTS + outbound call in one request. Require a "
        "recipient allowlist + per-campaign rate limit."
    ),
    "bland": (
        "Bland AI voice agent. Outbound LLM-driven call. Same shape as Retell/Vapi."
    ),
    "plivo": (
        "Outbound phone call via Plivo. Any number worldwide, premium-rate exposure, "
        "recipient can be victim of impersonation."
    ),
    "vonage": (
        "Outbound phone call via Vonage. Any number, any country."
    ),
    "daily": (
        "Video/voice room creation (Daily). A compromised agent can invite arbitrary "
        "participants to a room spoofed as legitimate."
    ),
    "elevenlabs": (
        "ElevenLabs voice synthesis. Real human voices clone from seconds of sample audio. "
        "If this repo also has outbound calls (Twilio/Retell/Vapi), an attacker has "
        "everything needed to impersonate someone on a phone call."
    ),
}

_FALLBACK = (
    "Voice / telephony action — agent places a call, sends synthesized audio, or creates "
    "a conference. Gate with @supervised('tool_use')."
)


def _emit(path: Path, line: int, snippet: str, provider: str, label: str,
          severity: str) -> Finding:
    return Finding(
        scanner="voice-actions",
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
