"""LEARN adapter (SUPERLOOP.md §6.7) — close the loop (R8).

Writes the learning + SCALE/ITERATE/HOLD/KILL move back onto the Decision Ledger
row so the next DECIDE can consult it.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ...models import SuperloopDecision
from ..domain import rules


class AprendizajePg:
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def aprender(self, decision: dict[str, Any], verif: dict[str, Any]) -> dict[str, Any]:
        estado = verif.get("estado_hipotesis")
        datos_suficientes = estado in ("sostuvo", "fallo")
        sostuvo = verif.get("hipotesis_sostuvo")
        movimiento = rules.determinar_scale_iterate_hold_kill(
            hipotesis_sostuvo=sostuvo,
            criterio_cumplido=sostuvo,
            datos_suficientes=datos_suficientes,
        )
        resultado = verif.get("resultado") or "No measured result."
        aprendizaje = (
            f"{resultado} Hypothesis {'held' if sostuvo else ('failed' if sostuvo is False else 'uncertain')}; "
            f"next move: {movimiento.value.upper()}."
        )

        row = self.db.get(SuperloopDecision, decision.get("decision_id"))
        if row is not None:
            row.resultado = resultado
            row.aprendizaje = aprendizaje
            row.siguiente_movimiento = movimiento.value
            self.db.flush()

        return {"aprendizaje": aprendizaje, "siguiente_movimiento": movimiento.value}
