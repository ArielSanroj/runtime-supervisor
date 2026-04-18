"""Threat detectors — stateless, regex/heuristic-based.

Each detector takes the inbound action payload (plus optional context for
stateful ones like velocity) and returns zero or more Signal objects.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Action


@dataclass(frozen=True)
class Signal:
    detector_id: str
    owasp_ref: str
    level: str  # info | warn | critical
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------- helpers ----------

def _walk_strings(obj: Any, path: str = "$") -> list[tuple[str, str]]:
    """Flatten any JSON payload into (jsonpath, string) tuples."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk_strings(v, f"{path}[{i}]"))
    elif isinstance(obj, str):
        out.append((path, obj))
    return out


# ---------- 1. Prompt injection ----------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore-previous", re.compile(r"ignore (all )?(previous|prior|above|earlier) (instructions|directions|rules)", re.I)),
    ("system-prompt", re.compile(r"(system prompt|system message|<\|im_start\|>|<\|im_end\|>)", re.I)),
    ("you-are-now", re.compile(r"you are (now|henceforth) (a|an|the)", re.I)),
    ("override", re.compile(r"(override|disregard|forget|bypass) (the )?(safety|guardrails?|rules|policy|policies)", re.I)),
    ("exfil-instruction", re.compile(r"(reveal|leak|print|output) (your |the )?(system )?(prompt|instructions|secrets?|keys?)", re.I)),
    ("invisible-unicode", re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")),
]


def detect_prompt_injection(payload: dict[str, Any], ctx: dict[str, Any]) -> list[Signal]:
    hits: list[Signal] = []
    for path, value in _walk_strings(payload):
        for rule_id, pat in _INJECTION_PATTERNS:
            m = pat.search(value)
            if m:
                hits.append(Signal(
                    detector_id="prompt-injection",
                    owasp_ref="LLM01",
                    level="critical",
                    message=f"Prompt-injection pattern '{rule_id}' matched at {path}",
                    evidence={"field": path, "pattern": rule_id, "match": m.group(0)[:80]},
                ))
                break  # one hit per field is enough
    return hits


# ---------- 2. Jailbreak / guardrail evasion ----------

_JAILBREAK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dan", re.compile(r"\bDAN\b|do anything now", re.I)),
    ("pretend-roleplay", re.compile(r"(pretend|act as|roleplay as) (you are|an? )?(jailbroken|uncensored|unrestricted)", re.I)),
    ("bypass-checks", re.compile(r"bypass (all|the) (safety |policy |internal )?(checks|controls|filters)", re.I)),
    ("hypothetical", re.compile(r"in a hypothetical (world|scenario) where (safety|rules|policy)", re.I)),
    ("evil-twin", re.compile(r"(evil|opposite|twin) (version|persona|mode) of (you|yourself)", re.I)),
]


def detect_jailbreak(payload: dict[str, Any], ctx: dict[str, Any]) -> list[Signal]:
    hits: list[Signal] = []
    for path, value in _walk_strings(payload):
        for rule_id, pat in _JAILBREAK_PATTERNS:
            m = pat.search(value)
            if m:
                hits.append(Signal(
                    detector_id="jailbreak",
                    owasp_ref="LLM06",
                    level="critical",
                    message=f"Jailbreak phrasing '{rule_id}' matched at {path}",
                    evidence={"field": path, "pattern": rule_id, "match": m.group(0)[:80]},
                ))
                break
    return hits


# ---------- 3. Hallucination / payload inconsistency ----------

ISO_4217 = {
    "USD", "EUR", "GBP", "JPY", "CNY", "MXN", "BRL", "COP", "ARS", "CLP", "PEN", "CAD", "AUD", "CHF",
    "INR", "KRW", "ZAR", "TRY", "NGN", "UYU",
}


def detect_hallucination(payload: dict[str, Any], ctx: dict[str, Any]) -> list[Signal]:
    hits: list[Signal] = []

    amount = payload.get("amount")
    if isinstance(amount, (int, float)) and amount < 0:
        hits.append(Signal(
            detector_id="hallucination", owasp_ref="LLM09", level="warn",
            message="Negative amount on a refund action — domain invariant violated",
            evidence={"field": "$.amount", "value": amount},
        ))

    currency = payload.get("currency")
    if isinstance(currency, str) and currency.upper() not in ISO_4217:
        hits.append(Signal(
            detector_id="hallucination", owasp_ref="LLM09", level="warn",
            message=f"Currency '{currency}' is not a known ISO-4217 code",
            evidence={"field": "$.currency", "value": currency},
        ))

    age = payload.get("customer_age_days")
    if isinstance(age, (int, float)) and age < 0:
        hits.append(Signal(
            detector_id="hallucination", owasp_ref="LLM09", level="warn",
            message="Negative customer age — hallucinated field",
            evidence={"field": "$.customer_age_days", "value": age},
        ))

    cid = payload.get("customer_id")
    if isinstance(cid, str) and len(cid.strip()) == 0:
        hits.append(Signal(
            detector_id="hallucination", owasp_ref="LLM09", level="warn",
            message="Empty customer_id string",
            evidence={"field": "$.customer_id"},
        ))

    # Future-dated timestamps on any ISO-ish field
    now = datetime.now(UTC)
    for path, value in _walk_strings(payload):
        if path.endswith("_at") or path.endswith("_time"):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                if dt > now + timedelta(minutes=5):
                    hits.append(Signal(
                        detector_id="hallucination", owasp_ref="LLM09", level="warn",
                        message=f"Future-dated timestamp at {path}",
                        evidence={"field": path, "value": value},
                    ))
            except ValueError:
                continue

    return hits


# ---------- 4. PII exfiltration ----------

_EMAIL = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PAN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PHONE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")

# Narrative fields where PII usually doesn't belong in a refund
NARRATIVE_FIELDS = ("reason", "notes", "description", "comment", "memo")


def detect_pii_exfil(payload: dict[str, Any], ctx: dict[str, Any]) -> list[Signal]:
    hits: list[Signal] = []
    for path, value in _walk_strings(payload):
        leaf = path.rsplit(".", 1)[-1]
        if leaf not in NARRATIVE_FIELDS:
            continue
        for label, pat in (("email", _EMAIL), ("ssn", _SSN), ("card", _PAN), ("phone", _PHONE)):
            m = pat.search(value)
            if m:
                hits.append(Signal(
                    detector_id="pii-exfil", owasp_ref="LLM02", level="warn",
                    message=f"{label.upper()} pattern in narrative field {path}",
                    evidence={"field": path, "pii_type": label, "match_preview": m.group(0)[:4] + "***"},
                ))
    return hits


# ---------- 5. Velocity / unbounded consumption ----------

VELOCITY_WINDOW_SECONDS = 60
VELOCITY_WARN = 10
VELOCITY_CRITICAL = 30


def detect_velocity(payload: dict[str, Any], ctx: dict[str, Any]) -> list[Signal]:
    db: Session | None = ctx.get("db")
    integration_id: str | None = ctx.get("integration_id")
    if db is None or integration_id is None or integration_id == "simulator":
        # Simulator marker: trust the payload's refund_velocity_24h hint to demo
        if payload.get("refund_velocity_24h") == 99:
            return [Signal(
                detector_id="unbounded-consumption", owasp_ref="LLM10", level="critical",
                message="Simulated burst: 42 actions in 60s from the same integration",
                evidence={"window_seconds": VELOCITY_WINDOW_SECONDS, "count": 42, "simulated": True},
            )]
        return []

    window_start = datetime.now(UTC) - timedelta(seconds=VELOCITY_WINDOW_SECONDS)
    count = db.execute(
        select(Action).where(Action.created_at >= window_start)
    ).scalars().all()
    n = len(count)
    if n >= VELOCITY_CRITICAL:
        level = "critical"
    elif n >= VELOCITY_WARN:
        level = "warn"
    else:
        return []
    return [Signal(
        detector_id="unbounded-consumption", owasp_ref="LLM10", level=level,
        message=f"{n} actions observed in the last {VELOCITY_WINDOW_SECONDS}s",
        evidence={"window_seconds": VELOCITY_WINDOW_SECONDS, "count": n},
    )]


# ---------- registry ----------

Detector = Callable[[dict[str, Any], dict[str, Any]], list[Signal]]

ALL_DETECTORS: list[Detector] = [
    detect_prompt_injection,
    detect_jailbreak,
    detect_hallucination,
    detect_pii_exfil,
    detect_velocity,
]
