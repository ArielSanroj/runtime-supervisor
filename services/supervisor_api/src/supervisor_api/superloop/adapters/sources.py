"""Data source adapter (SUPERLOOP.md §6.1) — OBSERVE over existing tables.

Read-only (R2). Builds a Snapshot from real rows:
  - repo unit       → Scan history (priority findings trend, scan recency)
  - supervisor unit → Decision / ReviewItem / PolicyRecord metrics (deny mix,
                      review backlog, whether the policy is still shadow)
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...models import Action, Decision, PolicyRecord, ReviewItem, Scan
from ..application.ports import FuenteDeDatos
from ..domain.entities import Afirmacion, Producto, Snapshot
from ..domain.enums import EtiquetaAfirmacion

_WINDOW_DAYS = 30


def _days_since(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return max(0.0, (datetime.now(UTC) - dt).total_seconds() / 86400.0)


class FuenteSupervisorApi(FuenteDeDatos):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def observar(self, producto: Producto) -> Snapshot:
        if producto.kind == "supervisor":
            return self._observar_supervisor(producto)
        return self._observar_repo(producto)

    # ---- repo unit ----
    def _observar_repo(self, producto: Producto) -> Snapshot:
        ahora = datetime.now(UTC).isoformat()
        repo_url = producto.source_ref or producto.nombre
        rows = self.db.execute(
            select(Scan)
            .where(Scan.repo_url == repo_url)
            .where(or_(Scan.tenant_id == self.tenant_id, Scan.tenant_id.is_(None)))
            .where(Scan.status == "done")
            .order_by(Scan.created_at.desc())
            .limit(2)
        ).scalars().all()

        if not rows:
            return Snapshot(
                producto_id=producto.producto_id, fecha=ahora,
                fuentes_consultadas=[], fuentes_inaccesibles=["scans"],
                datos_faltantes=["no_scans_on_record"],
                kpis={"metrica_principal": "priority_findings"},
                afirmaciones=[Afirmacion(
                    "No scan on record for this repo yet.", EtiquetaAfirmacion.PREGUNTA)],
            )

        latest = rows[0]
        prev = rows[1] if len(rows) > 1 else None
        priority = int(latest.priority_count or 0)
        risk_delta = (priority - int(prev.priority_count or 0)) if prev else None
        dias = _days_since(latest.created_at)

        kpis: dict[str, Any] = {
            "priority_findings": priority,
            "risk_count": priority,
            "total_findings": int(latest.total_findings or 0),
            "dias_desde_ultimo_uso": dias,
            "actividad_actual": len(rows),
            "metrica_principal": "priority_findings",
            "baseline_priority": priority,
            "scan_id": latest.id,
        }
        if risk_delta is not None:
            kpis["risk_delta"] = risk_delta

        afirm = [
            Afirmacion(
                f"Latest scan found {priority} priority finding(s) "
                f"of {int(latest.total_findings or 0)} total.",
                EtiquetaAfirmacion.HECHO),
            Afirmacion(
                f"Last scan {round(dias, 1) if dias is not None else '?'} day(s) ago.",
                EtiquetaAfirmacion.HECHO),
        ]
        if risk_delta is not None:
            afirm.append(Afirmacion(
                f"Priority findings changed by {risk_delta:+d} vs the previous scan.",
                EtiquetaAfirmacion.INFERENCIA))
        return Snapshot(
            producto_id=producto.producto_id, fecha=ahora,
            fuentes_consultadas=["scans"], kpis=kpis, afirmaciones=afirm,
        )

    # ---- supervisor unit ----
    def _observar_supervisor(self, producto: Producto) -> Snapshot:
        ahora = datetime.now(UTC).isoformat()
        action_type = producto.source_ref or producto.producto_id.split(":")[-1]
        since = datetime.now(UTC) - timedelta(days=_WINDOW_DAYS)

        rows = self.db.execute(
            select(Decision.decision, Action.shadow, func.count())
            .join(Action, Action.id == Decision.action_id)
            .where(Action.action_type == action_type)
            .where(Action.tenant_id == self.tenant_id)
            .where(Action.created_at >= since)
            .group_by(Decision.decision, Action.shadow)
        ).all()
        counts = {"allow": 0, "deny": 0, "review": 0}
        would_block_in_shadow = 0
        for decision, is_shadow, n in rows:
            counts[decision] = counts.get(decision, 0) + n
            if is_shadow and decision in ("deny", "review"):
                would_block_in_shadow += n
        total = sum(counts.values())

        backlog = self.db.execute(
            select(func.count())
            .select_from(ReviewItem)
            .join(Action, Action.id == ReviewItem.action_id)
            .where(Action.action_type == action_type)
            .where(ReviewItem.tenant_id == self.tenant_id)
            .where(ReviewItem.status == "pending")
        ).scalar_one()

        active_policies = self.db.execute(
            select(func.count())
            .select_from(PolicyRecord)
            .where(PolicyRecord.action_type == action_type)
            .where(PolicyRecord.is_active.is_(True))
        ).scalar_one()
        policy_shadow = active_policies == 0

        last_decision_at = self.db.execute(
            select(func.max(Action.created_at))
            .join(Decision, Decision.action_id == Action.id)
            .where(Action.action_type == action_type)
            .where(Action.tenant_id == self.tenant_id)
        ).scalar_one()
        dias = _days_since(last_decision_at)

        deny_rate = (counts["deny"] / total) if total else None
        kpis: dict[str, Any] = {
            "review_backlog": int(backlog),
            "decisions_total": total,
            "deny_rate": deny_rate,
            "would_block_in_shadow": would_block_in_shadow,
            "risk_count": int(backlog) + would_block_in_shadow,
            "policy_shadow": policy_shadow,
            "dias_desde_ultimo_uso": dias,
            "actividad_actual": total,
            "metrica_principal": "review_backlog",
        }

        fuentes = ["decisions", "review_items", "policies"]
        datos_faltantes = [] if total else ["no_decisions_in_window"]
        afirm = [
            Afirmacion(
                f"{total} decisions in {_WINDOW_DAYS}d: "
                f"{counts['allow']} allow / {counts['deny']} deny / {counts['review']} review.",
                EtiquetaAfirmacion.HECHO),
            Afirmacion(f"{int(backlog)} review(s) pending.", EtiquetaAfirmacion.HECHO),
        ]
        if policy_shadow:
            afirm.append(Afirmacion(
                f"No enforcing policy active for '{action_type}' — running in shadow.",
                EtiquetaAfirmacion.HECHO))
        if would_block_in_shadow:
            afirm.append(Afirmacion(
                f"{would_block_in_shadow} call(s) would have been blocked if enforced.",
                EtiquetaAfirmacion.HECHO))
        if not total:
            afirm.append(Afirmacion(
                f"No decisions for '{action_type}' in the last {_WINDOW_DAYS} days.",
                EtiquetaAfirmacion.PREGUNTA))
        return Snapshot(
            producto_id=producto.producto_id, fecha=ahora,
            fuentes_consultadas=fuentes, datos_faltantes=datos_faltantes,
            kpis=kpis, afirmaciones=afirm,
        )
