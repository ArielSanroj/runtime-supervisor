from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import Action, EvidenceEvent


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, seq: int, event_type: str, payload: dict[str, Any]) -> str:
    material = f"{prev_hash}|{seq}|{event_type}|{_canonical(payload)}"
    return hashlib.sha256(material.encode()).hexdigest()


def _genesis_hash(action_id: str) -> str:
    return hashlib.sha256(f"genesis:{action_id}".encode()).hexdigest()


def append(db: Session, *, action_id: str, event_type: str, payload: dict[str, Any]) -> EvidenceEvent:
    last = db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.action_id == action_id)
        .order_by(EvidenceEvent.seq.desc())
        .limit(1)
    ).scalar_one_or_none()

    if last is None:
        seq = 1
        prev = _genesis_hash(action_id)
    else:
        seq = last.seq + 1
        prev = last.hash

    h = _hash(prev, seq, event_type, payload)
    ev = EvidenceEvent(
        action_id=action_id,
        seq=seq,
        event_type=event_type,
        event_payload=payload,
        prev_hash=prev,
        hash=h,
    )
    db.add(ev)
    db.flush()
    return ev


def verify(db: Session, action_id: str) -> tuple[bool, int | None]:
    events = db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.action_id == action_id)
        .order_by(EvidenceEvent.seq.asc())
    ).scalars().all()

    expected_prev = _genesis_hash(action_id)
    for ev in events:
        if ev.prev_hash != expected_prev:
            return False, ev.seq
        recomputed = _hash(ev.prev_hash, ev.seq, ev.event_type, ev.event_payload)
        if recomputed != ev.hash:
            return False, ev.seq
        expected_prev = ev.hash
    return True, None


def bundle(db: Session, action_id: str) -> dict[str, Any]:
    action = db.get(Action, action_id)
    if action is None:
        raise LookupError(f"action {action_id} not found")

    events = db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.action_id == action_id)
        .order_by(EvidenceEvent.seq.asc())
    ).scalars().all()

    chain_ok, broken_at = verify(db, action_id)

    events_out = [
        {
            "seq": e.seq,
            "event_type": e.event_type,
            "event_payload": e.event_payload,
            "prev_hash": e.prev_hash,
            "hash": e.hash,
            "created_at": e.created_at,
        }
        for e in events
    ]

    tip_hash = events[-1].hash if events else _genesis_hash(action_id)
    bundle_hash = hashlib.sha256(
        f"{action_id}|{action.action_type}|{action.status}|{tip_hash}".encode()
    ).hexdigest()

    secret = get_settings().evidence_hmac_secret.encode()
    signature = hmac.new(secret, bundle_hash.encode(), hashlib.sha256).hexdigest()

    return {
        "action_id": action_id,
        "action_type": action.action_type,
        "status": action.status,
        "events": events_out,
        "chain_ok": chain_ok,
        "broken_at_seq": broken_at,
        "bundle_hash": bundle_hash,
        "bundle_signature": signature,
        "exported_at": datetime.now(UTC),
    }
