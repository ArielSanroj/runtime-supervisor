"""Approval gate adapter (SUPERLOOP.md §6.4, R1) — reuses the existing review queue.

A Level >= 3 Superloop decision becomes a synthetic Action + Decision(review) +
ReviewItem, so the existing `/v1/review-cases` dashboard and the tamper-evident
evidence chain handle the human gate with zero new approval plumbing. The
ReviewItem id is linked back onto the SuperloopDecision row.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ... import evidence
from ...models import Action, Decision, ReviewItem, SuperloopDecision
from ..application.ports import GateDeAprobacion

_ESTADO_MAP = {"pending": "pendiente", "approved": "aprobado", "rejected": "rechazado"}


class ReviewGate(GateDeAprobacion):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def solicitar(self, decision: dict[str, Any]) -> dict[str, Any]:
        nivel = int(decision.get("nivel_autonomia") or 0)
        if nivel < 3:
            return {"estado": "no_requiere_gate_humano", "review_item_id": None}

        # Already gated? (idempotent re-runs)
        sl = self.db.get(SuperloopDecision, decision["decision_id"])
        if sl is not None and sl.review_item_id:
            return self.estado(decision)

        action = Action(
            action_type="superloop_plan",
            status="received",
            payload={
                "superloop_decision_id": decision["decision_id"],
                "producto_id": decision.get("producto_id"),
                "nombre": decision.get("nombre"),
                "accion_tipo": decision.get("accion_tipo"),
                "decision_recomendada": decision.get("decision_recomendada"),
                "hipotesis": decision.get("hipotesis"),
                "metrica_objetivo": decision.get("metrica_objetivo"),
                "criterio_exito": decision.get("criterio_exito"),
                "nivel_autonomia": nivel,
            },
            shadow=False,
            tenant_id=self.tenant_id,
        )
        self.db.add(action)
        self.db.flush()

        self.db.add(Decision(
            action_id=action.id,
            decision="review",
            policy_hits=[],
            risk_score=80 if nivel >= 4 else 55,
            risk_breakdown=[{"source": "superloop", "nivel_autonomia": nivel}],
            policy_version="superloop@v1",
            tenant_id=self.tenant_id,
        ))
        review = ReviewItem(
            action_id=action.id,
            status="pending",
            priority="high" if nivel >= 4 else "normal",
            assigned_to="compliance" if nivel >= 4 else None,
            tenant_id=self.tenant_id,
        )
        self.db.add(review)
        self.db.flush()

        evidence.append(
            self.db, action_id=action.id, event_type="superloop.gate_opened",
            payload={
                "superloop_decision_id": decision["decision_id"],
                "nivel_autonomia": nivel,
                "decision_recomendada": decision.get("decision_recomendada"),
            },
            tenant_id=self.tenant_id,
        )

        if sl is not None:
            sl.review_item_id = review.id
        self.db.flush()
        return {
            "estado": "pendiente_aprobacion_humana",
            "review_item_id": review.id,
            "action_id": action.id,
        }

    def estado(self, decision: dict[str, Any]) -> dict[str, Any]:
        sl = self.db.get(SuperloopDecision, decision["decision_id"])
        if sl is None or not sl.review_item_id:
            return {"estado": "no_requiere_gate_humano", "review_item_id": None}
        item = self.db.get(ReviewItem, sl.review_item_id)
        if item is None:
            return {"estado": "pendiente", "review_item_id": sl.review_item_id}
        return {
            "estado": _ESTADO_MAP.get(item.status, "pendiente"),
            "review_item_id": item.id,
            "aprobador": item.approver,
        }
