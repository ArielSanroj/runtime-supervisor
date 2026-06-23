"""ORCHESTRATE executor (SUPERLOOP.md §6.5) — ALWAYS gated (R1).

Dispatches on `accion_tipo`. Conservative by default: `guard_stub` only drafts a
wrapper (no external side effect, Level 1); `promote_policy` flips the matching
PolicyRecord to active (the real Level 3 action, blocked unless a human approved);
`observe` is a no-op.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import PolicyRecord
from ..application.ports import EjecutorDeAcciones


def _action_type_of(producto_id: str) -> str:
    return producto_id.split(":", 1)[1] if ":" in producto_id else producto_id


class EjecutorSupervisorApi(EjecutorDeAcciones):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def ejecutar(self, decision: dict[str, Any]) -> dict[str, Any]:
        nivel = int(decision.get("nivel_autonomia") or 0)
        aprobador = decision.get("aprobador")
        # R1 — nothing with blast radius runs without a registered human approver.
        if nivel >= 3 and not aprobador:
            return {"accion_ejecutada": None, "aprobador": None,
                    "bloqueada_razon": "Level >= 3 action without human approver (R1)"}

        accion_tipo = decision.get("accion_tipo") or "observe"
        if accion_tipo == "promote_policy":
            return self._promote_policy(decision, aprobador)
        if accion_tipo == "guard_stub":
            return {
                "accion_ejecutada": (
                    "Drafted a guard wrapper for "
                    f"{decision.get('producto_id')}. Open a PR to apply it."),
                "aprobador": aprobador,
                "bloqueada_razon": None,
            }
        return {"accion_ejecutada": "No action required (observe).",
                "aprobador": aprobador, "bloqueada_razon": None}

    def _promote_policy(self, decision: dict[str, Any], aprobador: str | None) -> dict[str, Any]:
        action_type = _action_type_of(decision.get("producto_id", ""))
        rows = self.db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.action_type == action_type)
            .order_by(PolicyRecord.version.desc())
        ).scalars().all()
        if not rows:
            return {"accion_ejecutada": None, "aprobador": aprobador,
                    "bloqueada_razon": f"no policy version to promote for '{action_type}'"}
        target = next((r for r in rows if not r.is_active), rows[0])
        for r in rows:
            if r.is_active and r.id != target.id:
                r.is_active = False
        target.is_active = True
        self.db.flush()
        return {
            "accion_ejecutada": (
                f"Promoted policy '{action_type}' v{target.version} to enforce."),
            "aprobador": aprobador,
            "bloqueada_razon": None,
        }
