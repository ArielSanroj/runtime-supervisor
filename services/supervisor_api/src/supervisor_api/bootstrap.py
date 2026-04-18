"""Startup bootstrap: seed DB-managed policies from on-disk YAML.

Runs once when the API starts. Idempotent — if any policy row already
exists for an action_type, we leave it alone (the admin may have
intentionally deactivated it). Only seeds supervisors marked `live` in
the registry that have a `policy_ref` pointing at a YAML under
packages/policies/.
"""
from __future__ import annotations

import logging

from sqlalchemy import func, select

from . import registry
from .config import get_settings
from .db import SessionLocal
from .engines.policy import resolve_policy_path
from .models import PolicyRecord

log = logging.getLogger(__name__)


def seed_policies_from_yaml() -> list[str]:
    """Create DB policy rows from YAML when no row exists for that action_type.

    Returns the list of action_type ids that got seeded.
    """
    settings = get_settings()
    seeded: list[str] = []
    db = SessionLocal()
    try:
        for spec in registry.REGISTRY:
            if spec.status != "live" or spec.policy_ref is None:
                continue
            existing = db.execute(
                select(func.count()).select_from(PolicyRecord).where(PolicyRecord.action_type == spec.id)
            ).scalar_one()
            if existing > 0:
                continue
            path = resolve_policy_path(spec.id, settings.repo_root)
            if not path.exists():
                log.warning("No YAML at %s for live action_type %s", path, spec.id)
                continue
            yaml_source = path.read_text()
            record = PolicyRecord(
                action_type=spec.id,
                name=spec.policy_ref.split("@")[0],
                version=1,
                yaml_source=yaml_source,
                is_active=True,
                created_by="bootstrap",
            )
            db.add(record)
            seeded.append(spec.id)
        if seeded:
            db.commit()
            log.info("Seeded policies from YAML for: %s", seeded)
    finally:
        db.close()
    return seeded
