"""Decision Ledger adapter (SUPERLOOP.md §11) — SuperloopDecision table (R8).

Append-only trace of decisions, approvals, executions and learnings. DECIDE reads
`ultimos_aprendizajes` before recommending, so REPEAT actually learns.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import SuperloopDecision
from ..application.ports import DecisionLedger
from ..domain.entities import Aprendizaje, DecisionRecomendada
from ..domain.enums import SiguienteMovimiento


class DecisionLedgerPg(DecisionLedger):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def registrar(self, decision: DecisionRecomendada) -> str:
        row = SuperloopDecision(
            decision_id=decision.decision_id,
            producto_id=decision.producto_id,
            tenant_id=self.tenant_id,
            ciclo_id=decision.ciclo_id,
            fase_origen=decision.fase_origen,
            decision_recomendada=decision.decision_recomendada,
            accion_tipo=decision.accion_tipo,
            hipotesis=decision.hipotesis,
            metrica_objetivo=decision.metrica_objetivo,
            criterio_exito=decision.criterio_exito,
            ventana_medicion=decision.ventana_medicion,
            nivel_autonomia=int(decision.nivel_autonomia.value),
            riesgo=decision.riesgo,
            razonamiento=decision.razonamiento,
            opciones_consideradas=decision.opciones_consideradas,
            datos_usados=decision.datos_usados,
            afirmaciones=[a.to_dict() for a in decision.afirmaciones],
            estado_aprobacion=decision.estado_aprobacion.value,
        )
        self.db.add(row)
        self.db.flush()
        return row.decision_id

    def get(self, decision_id: str) -> dict[str, Any] | None:
        row = self.db.get(SuperloopDecision, decision_id)
        return _to_dict(row) if row else None

    def ultimos_aprendizajes(self, producto_id: str, limit: int = 5) -> list[Aprendizaje]:
        rows = self.db.execute(
            select(SuperloopDecision)
            .where(SuperloopDecision.producto_id == producto_id)
            .where(SuperloopDecision.aprendizaje.is_not(None))
            .order_by(SuperloopDecision.created_at.desc())
            .limit(limit)
        ).scalars().all()
        out: list[Aprendizaje] = []
        for r in rows:
            try:
                mov = SiguienteMovimiento(r.siguiente_movimiento) if r.siguiente_movimiento else SiguienteMovimiento.HOLD
            except ValueError:
                mov = SiguienteMovimiento.HOLD
            out.append(Aprendizaje(
                producto_id=r.producto_id,
                hipotesis=r.hipotesis or "",
                resultado=r.resultado or "",
                aprendizaje=r.aprendizaje or "",
                siguiente_movimiento=mov,
                fecha=r.created_at.isoformat() if r.created_at else "",
            ))
        return out

    def actualizar_aprobacion(self, decision_id: str, estado: str,
                              aprobador: str | None) -> None:
        row = self.db.get(SuperloopDecision, decision_id)
        if row is None:
            return
        row.estado_aprobacion = estado
        if aprobador is not None:
            row.aprobador = aprobador
        self.db.flush()


def _to_dict(row: SuperloopDecision) -> dict[str, Any]:
    return {
        "decision_id": row.decision_id,
        "producto_id": row.producto_id,
        "tenant_id": row.tenant_id,
        "ciclo_id": row.ciclo_id,
        "fase_origen": row.fase_origen,
        "decision_recomendada": row.decision_recomendada,
        "accion_tipo": row.accion_tipo,
        "hipotesis": row.hipotesis,
        "metrica_objetivo": row.metrica_objetivo,
        "criterio_exito": row.criterio_exito,
        "ventana_medicion": row.ventana_medicion,
        "nivel_autonomia": row.nivel_autonomia,
        "riesgo": row.riesgo,
        "razonamiento": row.razonamiento,
        "opciones_consideradas": row.opciones_consideradas,
        "datos_usados": row.datos_usados,
        "afirmaciones": row.afirmaciones,
        "estado_aprobacion": row.estado_aprobacion,
        "aprobador": row.aprobador,
        "review_item_id": row.review_item_id,
        "accion_ejecutada": row.accion_ejecutada,
        "resultado": row.resultado,
        "aprendizaje": row.aprendizaje,
        "siguiente_movimiento": row.siguiente_movimiento,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
