"""Admin audit logger.

Records every admin-scoped action (promote policy, revoke integration,
change webhook subscription, rotate secret, etc.) to the admin_events
table. Read-only for operators via /v1/admin/events.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import AdminEvent


def record(
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    db: Session | None = None,
) -> None:
    """Best-effort: never raise. Uses passed db or a private session."""
    own = db is None
    s = db or SessionLocal()
    try:
        s.add(
            AdminEvent(
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details or {},
                ip_address=ip_address,
            )
        )
        if own:
            s.commit()
    except Exception:
        if own:
            s.rollback()
    finally:
        if own:
            s.close()
