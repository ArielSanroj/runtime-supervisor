"""Superloop facade (SUPERLOOP.md §1, §12) — single entry point.

Wires the hexagonal adapters onto a request-scoped SQLAlchemy session + tenant,
runs the read-only loop (OBSERVE→DIAGNOSE→DECIDE, stops at APPROVE for the human
gate, R1) over repos and/or supervisors, and — separately — resumes the gated
tail (ORCHESTRATE→VERIFY→LEARN) over approved decisions to close the loop (R8).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import evidence
from ..models import (
    Action,
    ReviewItem,
    SuperloopCycle,
    SuperloopDecision,
    SuperloopProduct,
)
from .adapters.clock import IdentidadUUID, TiempoUTC
from .adapters.executor import EjecutorSupervisorApi
from .adapters.learn import AprendizajePg
from .adapters.ledger_pg import DecisionLedgerPg
from .adapters.registry_pg import RegistroCanonicoPg
from .adapters.renderer import build_cards
from .adapters.review_gate import ReviewGate
from .adapters.sources import FuenteSupervisorApi
from .adapters.verifier import VerificadorSupervisorApi
from .application.state_machine import PhaseNotDone, SuperloopStateMachine
from .application.use_cases import (
    DecidirProximaAccion,
    DiagnosticarProducto,
    ObservarProducto,
    OrquestarAccionAprobada,
    RegistrarAprendizaje,
    VerificarResultado,
)
from .domain import phase_done
from .domain.entities import Producto
from .products import discover

_VERDICT_TO_ESTADO = {
    "approved": "aprobado",
    "rejected": "rechazado",
    "requires_changes": "requiere_cambios",
}
_VERDICT_TO_REVIEW = {
    "approved": "approved",
    "rejected": "rejected",
    "requires_changes": "rejected",
}


class SuperloopFacade:
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id
        self.tiempo = TiempoUTC()
        self.identidad = IdentidadUUID()
        self.registro = RegistroCanonicoPg(db, tenant_id)
        self.ledger = DecisionLedgerPg(db, tenant_id)
        self.fuente = FuenteSupervisorApi(db, tenant_id)
        self.gate = ReviewGate(db, tenant_id)
        self.ejecutor = EjecutorSupervisorApi(db, tenant_id)
        self.verificador = VerificadorSupervisorApi(db, tenant_id)
        self.aprendiz = AprendizajePg(db, tenant_id)

        use_cases = {
            "observe": ObservarProducto(self.fuente, self.registro, self.tiempo),
            "diagnose": DiagnosticarProducto(self.registro),
            "decide": DecidirProximaAccion(self.registro, self.ledger, self.tiempo, self.identidad),
        }
        # MVP read-only run stops at APPROVE (human gate, R1).
        self.machine = SuperloopStateMachine(use_cases, detener_en="approve")
        self._orquestar = OrquestarAccionAprobada(self.ejecutor)
        self._verificar = VerificarResultado(self.verificador)
        self._aprender = RegistrarAprendizaje(self.aprendiz)

    # ---- OBSERVE → DECIDE (stops at APPROVE) ----
    def run(self, scope: str = "all") -> dict[str, Any]:
        run_id = self.identidad.nuevo_id("run")
        productos = discover(self.db, self.tenant_id, scope)
        cards = [self._run_producto(p, run_id, scope) for p in productos]
        self.db.commit()
        return {"run_id": run_id, "scope": scope, "count": len(cards), "cards": cards}

    def _run_producto(self, producto: Producto, run_id: str, scope: str) -> dict[str, Any]:
        ciclo_id = self.identidad.nuevo_id("cyc")
        try:
            resultado = self.machine.run(producto)
        except PhaseNotDone as exc:
            cards = build_cards(producto, None, None, str(exc))
            self._persist_cycle(ciclo_id, run_id, producto, scope, None, str(exc), cards)
            return cards

        decide = resultado.registros.get("decide", {})
        gate: dict[str, Any] = {}
        decision_id = decide.get("decision_id")
        if decide.get("requiere_aprobacion") and decision_id:
            gate = self.gate.solicitar({
                "decision_id": decision_id,
                "producto_id": producto.producto_id,
                "nombre": producto.nombre,
                "nivel_autonomia": decide.get("nivel_autonomia"),
                "accion_tipo": decide.get("accion_tipo"),
                "decision_recomendada": decide.get("decision_recomendada"),
                "hipotesis": decide.get("hipotesis"),
                "metrica_objetivo": decide.get("metrica_objetivo"),
                "criterio_exito": decide.get("criterio_exito"),
            })
        # Tie the decision to this cycle.
        if decision_id:
            row = self.db.get(SuperloopDecision, decision_id)
            if row is not None:
                row.ciclo_id = ciclo_id

        cards = build_cards(producto, resultado, gate, None)
        self._persist_cycle(ciclo_id, run_id, producto, scope,
                            resultado.fase_alcanzada, None, cards,
                            detenido_en=resultado.detenido_en)
        # Mirror approval state onto the canonical product row.
        prod_row = self.db.get(SuperloopProduct, producto.producto_id)
        if prod_row is not None:
            prod_row.ultimo_ciclo = {
                "ciclo_id": ciclo_id, "run_id": run_id,
                "at": datetime.now(UTC).isoformat(),
                "decision_id": decision_id,
                "fase_alcanzada": resultado.fase_alcanzada,
            }
            if gate.get("estado"):
                mapped = {"pendiente_aprobacion_humana": "pendiente"}.get(
                    gate["estado"], gate["estado"])
                prod_row.estado_aprobacion = mapped
        return cards

    def _persist_cycle(self, ciclo_id: str, run_id: str, producto: Producto, scope: str,
                       fase_alcanzada: str | None, error: str | None,
                       cards: dict[str, Any], detenido_en: str | None = None) -> None:
        self.db.add(SuperloopCycle(
            id=ciclo_id,
            run_id=run_id,
            producto_id=producto.producto_id,
            tenant_id=self.tenant_id,
            scope=scope,
            fase_alcanzada=fase_alcanzada or "observe",
            detenido_en=detenido_en,
            business_card=cards.get("business_card") or {},
            evidence_pack=cards.get("evidence_pack") or {},
            error=error,
        ))
        self.db.flush()

    # ---- read views ----
    def registry(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(SuperloopProduct)
            .where(SuperloopProduct.tenant_id == self.tenant_id)
            .order_by(SuperloopProduct.updated_at.desc())
        ).scalars().all()
        return [{
            "producto_id": r.producto_id,
            "kind": r.kind,
            "nombre": r.nombre,
            "estado_operativo": r.estado_operativo,
            "estado_comercial": r.estado_comercial,
            "confianza_estado": r.confianza_estado,
            "metrica_principal": r.metrica_principal,
            "proxima_mejor_accion": r.proxima_mejor_accion,
            "estado_aprobacion": r.estado_aprobacion,
            "decision_recomendada_ref": r.decision_recomendada_ref,
            "ultimo_ciclo": r.ultimo_ciclo,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        } for r in rows]

    def cola_hitl(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(SuperloopDecision)
            .where(SuperloopDecision.tenant_id == self.tenant_id)
            .where(SuperloopDecision.nivel_autonomia >= 3)
            .where(SuperloopDecision.estado_aprobacion == "pendiente")
            .order_by(SuperloopDecision.nivel_autonomia.desc(),
                      SuperloopDecision.created_at.desc())
        ).scalars().all()
        out = []
        for r in rows:
            cyc = self.db.get(SuperloopCycle, r.ciclo_id) if r.ciclo_id else None
            out.append({
                "decision_id": r.decision_id,
                "producto_id": r.producto_id,
                "review_item_id": r.review_item_id,
                "nivel_autonomia": r.nivel_autonomia,
                "business_card": cyc.business_card if cyc else None,
                "evidence_pack": cyc.evidence_pack if cyc else None,
            })
        return out

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(SuperloopCycle)
            .where(SuperloopCycle.tenant_id == self.tenant_id)
            .order_by(SuperloopCycle.created_at.desc())
            .limit(limit)
        ).scalars().all()
        runs: dict[str, dict[str, Any]] = {}
        for r in rows:
            g = runs.setdefault(r.run_id, {
                "run_id": r.run_id, "scope": r.scope, "count": 0,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            })
            g["count"] += 1
        return list(runs.values())

    def run_detail(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(SuperloopCycle)
            .where(SuperloopCycle.tenant_id == self.tenant_id)
            .where(SuperloopCycle.run_id == run_id)
            .order_by(SuperloopCycle.created_at.asc())
        ).scalars().all()
        return [{
            "ciclo_id": r.id,
            "producto_id": r.producto_id,
            "fase_alcanzada": r.fase_alcanzada,
            "detenido_en": r.detenido_en,
            "business_card": r.business_card,
            "evidence_pack": r.evidence_pack,
            "error": r.error,
        } for r in rows]

    # ---- APPROVE (human verdict via the review queue, R1) ----
    def aprobar(self, decision_id: str, aprobador: str, verdict: str) -> dict[str, Any]:
        if verdict not in _VERDICT_TO_ESTADO:
            raise ValueError(f"unknown verdict: {verdict!r}")
        if not aprobador:
            raise ValueError("human approver required (R1)")
        row = self.db.get(SuperloopDecision, decision_id)
        if row is None or row.tenant_id != self.tenant_id:
            raise LookupError("decision not found")

        estado = _VERDICT_TO_ESTADO[verdict]
        if row.review_item_id:
            item = self.db.get(ReviewItem, row.review_item_id)
            if item is not None and item.status == "pending":
                item.status = _VERDICT_TO_REVIEW[verdict]
                item.approver = aprobador
                item.resolved_at = datetime.now(UTC)
                action = self.db.get(Action, item.action_id)
                if action is not None:
                    action.status = "approved" if verdict == "approved" else "rejected"
                    evidence.append(
                        self.db, action_id=action.id,
                        event_type="superloop.gate_resolved",
                        payload={"verdict": verdict, "approver": aprobador,
                                 "superloop_decision_id": decision_id},
                        tenant_id=self.tenant_id,
                    )
        self.ledger.actualizar_aprobacion(decision_id, estado, aprobador)
        prod = self.db.get(SuperloopProduct, row.producto_id)
        if prod is not None:
            prod.estado_aprobacion = estado
        self.db.commit()
        return {"decision_id": decision_id, "estado_aprobacion": estado, "aprobador": aprobador}

    # ---- ORCHESTRATE → VERIFY → LEARN (close the loop, R8) ----
    def resume_aprobados(self) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(SuperloopDecision)
            .where(SuperloopDecision.tenant_id == self.tenant_id)
            .where(SuperloopDecision.aprendizaje.is_(None))
            .where(
                (SuperloopDecision.nivel_autonomia < 3)
                | (SuperloopDecision.estado_aprobacion == "aprobado")
            )
            .order_by(SuperloopDecision.created_at.asc())
        ).scalars().all()
        salidas = [self._cerrar_ciclo(self._decision_dict(r)) for r in rows]
        self.db.commit()
        return salidas

    @staticmethod
    def _decision_dict(r: SuperloopDecision) -> dict[str, Any]:
        return {
            "decision_id": r.decision_id,
            "producto_id": r.producto_id,
            "accion_tipo": r.accion_tipo,
            "nivel_autonomia": r.nivel_autonomia,
            "aprobador": r.aprobador,
            "estado_aprobacion": r.estado_aprobacion,
            "datos_usados": r.datos_usados or {},
            "hipotesis": r.hipotesis,
            "criterio_exito": r.criterio_exito,
        }

    def _cerrar_ciclo(self, decision: dict[str, Any]) -> dict[str, Any]:
        contexto: dict[str, Any] = {}
        orq = self._orquestar(decision, contexto)
        ok, faltan = phase_done.orchestrate_done({**decision, **orq})
        if not ok:
            return {"decision_id": decision["decision_id"], "fase": "orchestrate",
                    "ok": False, "faltan": faltan, "detalle": orq}
        ver = self._verificar(decision, contexto)
        ok, faltan = phase_done.verify_done(ver)
        if not ok:
            return {"decision_id": decision["decision_id"], "fase": "verify",
                    "ok": False, "faltan": faltan, "detalle": ver}
        learn = self._aprender(decision, contexto)
        ok, faltan = phase_done.learn_done(learn)
        return {
            "decision_id": decision["decision_id"],
            "fase": "learn" if ok else "learn_incompleto",
            "ok": ok, "faltan": faltan,
            "siguiente_movimiento": learn.get("siguiente_movimiento"),
            "aprendizaje": learn.get("aprendizaje"),
        }
