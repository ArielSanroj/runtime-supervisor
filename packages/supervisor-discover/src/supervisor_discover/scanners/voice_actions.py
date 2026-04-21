"""Detect voice / telephony actions — the agent can make phone calls.

Scope: outbound calls, voice synthesis, call transfers. These are real-world
high-impact actions (the agent dials a human, a clone-voice speaks, costs
money per-minute, can be weaponized for social-engineering / vishing).

Providers covered: Twilio (Voice), Retell, Vapi, Bland, Daily, Agora, Plivo,
Vonage, ElevenLabs (text-to-speech + voice cloning).
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

# (pattern, provider, what-it-does, severity)
_SIGNATURES: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\btwilio[\w.]*\.calls\.create\s*\("), "twilio", "outbound phone call", "high"),
    (re.compile(r"\btwilio[\w.]*\.conferences\b"), "twilio", "conference bridge", "medium"),
    (re.compile(r"\bretell[\w.]*\.(call|phone_call|createPhoneCall)\b"), "retell", "AI voice agent call", "high"),
    (re.compile(r"\bvapi[\w.]*\.calls\.create\s*\("), "vapi", "AI voice agent call", "high"),
    (re.compile(r"\bbland[\w.]*\.calls\.create\s*\("), "bland", "AI voice agent call", "high"),
    (re.compile(r"\bplivo[\w.]*\.calls\.create\s*\("), "plivo", "outbound phone call", "high"),
    (re.compile(r"\bvonage[\w.]*\.calls\.create\s*\("), "vonage", "outbound phone call", "high"),
    (re.compile(r"\bdaily[\w.]*\.(rooms|createRoom)\b"), "daily", "video room creation", "medium"),
    (re.compile(r"\belevenlabs[\w.]*\.(generate|text_to_speech|textToSpeech|tts)\b", re.I),
     "elevenlabs", "voice synthesis (possible clone)", "high"),
    (re.compile(r"\b(?:client|xi)\.voices\.(add|clone)\b", re.I), "elevenlabs", "voice cloning", "high"),
    # Raw HTTP hits — catches cases where the SDK isn't imported but they hit the API directly.
    (re.compile(r"api\.twilio\.com/\S*(?:Calls|Conferences)"), "twilio", "raw Twilio voice API call", "high"),
    (re.compile(r"api\.elevenlabs\.io/\S*(?:text-to-speech|voices)"), "elevenlabs", "raw ElevenLabs API call", "high"),
    (re.compile(r"api\.retellai\.com/\S*"), "retell", "raw Retell API call", "high"),
    (re.compile(r"api\.vapi\.ai/\S*"), "vapi", "raw Vapi API call", "high"),
]

# Per-provider narratives — each describes the concrete worst-case, not a
# generic category blurb. The report reads much closer to how a security
# reviewer would talk about the risk.
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


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        for pattern, provider, label, severity in _SIGNATURES:
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="voice-actions",
                    file=str(path),
                    line=line,
                    snippet=m.group(0)[:80],
                    suggested_action_type="tool_use",
                    confidence=severity,
                    rationale=_NARRATIVES.get(provider, _FALLBACK),
                    extra={"provider": provider, "label": label},
                ))
    return findings
