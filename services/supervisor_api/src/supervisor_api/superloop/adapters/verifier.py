"""VERIFY adapter (SUPERLOOP.md §6.6) — measure against data (R7).

Honest by default: if there isn't enough fresh data to judge (e.g. no new scan
after a drafted guard), the hypothesis is 'incierta' and LEARN will HOLD.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import PolicyRecord, Scan
from ..application.ports import Verificador


def _action_type_of(producto_id: str) -> str:
    return producto_id.split(":", 1)[1] if ":" in producto_id else producto_id


class VerificadorSupervisorApi(Verificador):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def verificar(self, decision: dict[str, Any]) -> dict[str, Any]:
        accion_tipo = decision.get("accion_tipo") or "observe"
        if accion_tipo == "promote_policy":
            return self._verify_policy(decision)
        if accion_tipo == "guard_stub":
            return self._verify_repo(decision)
        return {
            "hipotesis_sostuvo": None,
            "estado_hipotesis": "incierta",
            "resultado": "Observe-only decision — nothing to measure.",
        }

    def _verify_policy(self, decision: dict[str, Any]) -> dict[str, Any]:
        action_type = _action_type_of(decision.get("producto_id", ""))
        active = self.db.execute(
            select(func.count())
            .select_from(PolicyRecord)
            .where(PolicyRecord.action_type == action_type)
            .where(PolicyRecord.is_active.is_(True))
        ).scalar_one()
        if active:
            return {
                "hipotesis_sostuvo": True,
                "estado_hipotesis": "sostuvo",
                "resultado": f"Policy '{action_type}' is now enforcing ({active} active).",
            }
        return {
            "hipotesis_sostuvo": False,
            "estado_hipotesis": "fallo",
            "resultado": f"No enforcing policy active for '{action_type}' after orchestrate.",
        }

    def _verify_repo(self, decision: dict[str, Any]) -> dict[str, Any]:
        datos = decision.get("datos_usados") or {}
        kpis = datos.get("kpis") or {}
        baseline = kpis.get("baseline_priority")
        repo_url = None
        # producto_id is repo:<sha>; we kept repo_url only in the snapshot, so fall
        # back to comparing the two most recent scans for this product's repo by
        # re-reading from the registry hint when present.
        scan_id = kpis.get("scan_id")
        latest = None
        if scan_id is not None:
            base_scan = self.db.get(Scan, scan_id)
            if base_scan is not None:
                repo_url = base_scan.repo_url
        if repo_url is not None:
            latest = self.db.execute(
                select(Scan)
                .where(Scan.repo_url == repo_url)
                .where(Scan.status == "done")
                .order_by(Scan.created_at.desc())
                .limit(1)
            ).scalars().first()
        if latest is None or baseline is None or latest.id == scan_id:
            return {
                "hipotesis_sostuvo": None,
                "estado_hipotesis": "incierta",
                "resultado": "No fresh scan since the guard was drafted — re-scan to verify.",
            }
        now_priority = int(latest.priority_count or 0)
        if now_priority < int(baseline):
            return {
                "hipotesis_sostuvo": True,
                "estado_hipotesis": "sostuvo",
                "resultado": f"Priority findings dropped {int(baseline)} → {now_priority} after the guard.",
            }
        return {
            "hipotesis_sostuvo": False,
            "estado_hipotesis": "fallo",
            "resultado": f"Priority findings did not drop (still {now_priority}).",
        }
