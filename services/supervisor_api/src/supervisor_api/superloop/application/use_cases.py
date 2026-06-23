"""Superloop use cases (SUPERLOOP.md §6) — one callable per phase.

OBSERVE / DIAGNOSE / DECIDE feed the read-only run (stops at APPROVE, R1).
ORCHESTRATE / VERIFY / LEARN are driven by the facade's resume path after a human
approves a gated decision.
"""
from __future__ import annotations

from typing import Any

from ..domain import rules
from ..domain.entities import (
    Afirmacion,
    Diagnostico,
    DecisionRecomendada,
    Producto,
    RegistroCanonicoEntry,
    Snapshot,
)
from ..domain.enums import EstadoAprobacion, EtiquetaAfirmacion, NivelAutonomia
from .ports import (
    DecisionLedger,
    FuenteDeDatos,
    ProveedorDeIdentidad,
    ProveedorDeTiempo,
    RegistroCanonico,
)


class ObservarProducto:
    """OBSERVE (§6.1) — collect signals, persist a Snapshot. Read-only (R2)."""

    def __init__(self, fuente: FuenteDeDatos, registro: RegistroCanonico,
                 tiempo: ProveedorDeTiempo):
        self.fuente = fuente
        self.registro = registro
        self.tiempo = tiempo

    def __call__(self, producto: Producto, contexto: dict[str, Any]) -> dict[str, Any]:
        snapshot = self.fuente.observar(producto)
        contexto["snapshot"] = snapshot
        self.registro.append_history(
            producto.producto_id, "observe",
            {
                "kpis": snapshot.kpis,
                "fuentes_consultadas": snapshot.fuentes_consultadas,
                "fuentes_inaccesibles": snapshot.fuentes_inaccesibles,
                "datos_faltantes": snapshot.datos_faltantes,
            },
            ciclo_id=contexto.get("ciclo_id"),
        )
        return {
            "snapshot_fecha": snapshot.fecha,
            "fuentes_consultadas": snapshot.fuentes_consultadas,
            "fuentes_inaccesibles": snapshot.fuentes_inaccesibles,
            "datos_faltantes": snapshot.datos_faltantes,
            "afirmaciones": [a.to_dict() for a in snapshot.afirmaciones],
            "kpis": snapshot.kpis,
        }


class DiagnosticarProducto:
    """DIAGNOSE (§6.2) — classify state, detect anomalies, label claims (R3)."""

    def __init__(self, registro: RegistroCanonico):
        self.registro = registro

    def __call__(self, producto: Producto, contexto: dict[str, Any]) -> dict[str, Any]:
        snapshot: Snapshot = contexto["snapshot"]
        senales = dict(snapshot.kpis)

        estado_op, conf_op = rules.clasificar_estado_operativo(senales)
        estado_com, conf_com = rules.clasificar_estado_comercial(senales)
        anomalias = rules.detectar_anomalias(senales)
        confianza = round((conf_op + conf_com) / 2, 2)
        metrica = rules.metrica_principal(producto.kind, senales)

        # R3 — labeled claims (inherit OBSERVE's + add the diagnosis').
        afirmaciones: list[Afirmacion] = list(snapshot.afirmaciones)
        afirmaciones.append(Afirmacion(
            f"Usage state classified as {estado_op.value} (confidence {conf_op}).",
            EtiquetaAfirmacion.INFERENCIA,
        ))
        afirmaciones.append(Afirmacion(
            f"Risk posture classified as {estado_com.value} (confidence {conf_com}).",
            EtiquetaAfirmacion.INFERENCIA,
        ))
        for a in anomalias:
            afirmaciones.append(Afirmacion(f"Trigger detected: {a}.", EtiquetaAfirmacion.HECHO))
        if snapshot.datos_faltantes:
            afirmaciones.append(Afirmacion(
                f"Missing data: {', '.join(snapshot.datos_faltantes)}.",
                EtiquetaAfirmacion.PREGUNTA,
            ))

        diagnostico = Diagnostico(
            producto_id=producto.producto_id,
            estado_operativo=estado_op,
            estado_comercial=estado_com,
            confianza=confianza,
            metrica_principal=metrica,
            kpis=senales,
            anomalias=anomalias,
            afirmaciones=afirmaciones,
        )
        contexto["diagnostico"] = diagnostico

        self.registro.upsert(RegistroCanonicoEntry(
            producto_id=producto.producto_id,
            kind=producto.kind,
            nombre=producto.nombre,
            estado_operativo=estado_op.value,
            estado_comercial=estado_com.value,
            confianza_estado=confianza,
            metrica_principal=metrica,
            kpis=senales,
            afirmaciones=[a.to_dict() for a in afirmaciones],
        ))

        return {
            "estado_operativo": estado_op.value,
            "estado_comercial": estado_com.value,
            "confianza": confianza,
            "metrica_principal": metrica,
            "anomalias": anomalias,
            "afirmaciones": [a.to_dict() for a in afirmaciones],
            "kpis": senales,
        }


class DecidirProximaAccion:
    """DECIDE (§6.3) — turn the diagnosis into an approvable decision (R6).

    R8 — consults the product's accumulated learning BEFORE deciding.
    """

    def __init__(self, registro: RegistroCanonico, ledger: DecisionLedger,
                 tiempo: ProveedorDeTiempo, identidad: ProveedorDeIdentidad):
        self.registro = registro
        self.ledger = ledger
        self.tiempo = tiempo
        self.identidad = identidad

    def __call__(self, producto: Producto, contexto: dict[str, Any]) -> dict[str, Any]:
        diagnostico: Diagnostico = contexto["diagnostico"]

        # R8 — the loop is only closed if LEARN feeds the next DECIDE.
        aprendizajes = self.ledger.ultimos_aprendizajes(producto.producto_id, limit=5)
        contexto["aprendizajes_previos"] = aprendizajes

        plan = rules.plan_siguiente_accion(
            producto.kind, diagnostico.estado_operativo, diagnostico.estado_comercial,
            diagnostico.kpis,
        )
        nivel = plan["nivel"] if isinstance(plan["nivel"], NivelAutonomia) else NivelAutonomia(plan["nivel"])

        razonamiento = (
            f"Unit in usage={diagnostico.estado_operativo.value}, "
            f"risk_posture={diagnostico.estado_comercial.value}. "
            f"{len(aprendizajes)} prior learning(s) consulted (R8)."
        )
        if aprendizajes:
            razonamiento += " Last: " + aprendizajes[0].aprendizaje

        decision = DecisionRecomendada(
            decision_id=self.identidad.nuevo_id("dec"),
            producto_id=producto.producto_id,
            fecha=self.tiempo.ahora(),
            fase_origen="decide",
            decision_recomendada=plan["accion"],
            accion_tipo=plan["accion_tipo"],
            hipotesis=plan["hipotesis"],
            metrica_objetivo=plan["metrica"],
            criterio_exito=plan["criterio_exito"],
            ventana_medicion="14 days",
            nivel_autonomia=nivel,
            segmento=producto.cliente_ideal,
            impacto_esperado="medium",
            esfuerzo_estimado="low",
            riesgo=plan["riesgo"],
            razonamiento=razonamiento,
            opciones_consideradas=[
                {"opcion": plan["accion"], "elegida": True},
                {"opcion": "Keep observing (HOLD)", "elegida": False},
            ],
            datos_usados={"kpis": diagnostico.kpis, "anomalias": diagnostico.anomalias},
            afirmaciones=diagnostico.afirmaciones,
            estado_aprobacion=EstadoAprobacion.PENDIENTE,
            ciclo_id=contexto.get("ciclo_id"),
        )
        contexto["decision"] = decision
        self.ledger.registrar(decision)

        self.registro.upsert(RegistroCanonicoEntry(
            producto_id=producto.producto_id,
            kind=producto.kind,
            nombre=producto.nombre,
            estado_operativo=diagnostico.estado_operativo.value,
            estado_comercial=diagnostico.estado_comercial.value,
            confianza_estado=diagnostico.confianza,
            metrica_principal=diagnostico.metrica_principal,
            kpis=diagnostico.kpis,
            afirmaciones=[a.to_dict() for a in diagnostico.afirmaciones],
            hipotesis_vigente=decision.hipotesis,
            decision_recomendada_ref=decision.decision_id,
            estado_aprobacion=EstadoAprobacion.PENDIENTE.value,
            proxima_mejor_accion=plan["accion"],
        ))

        return {
            "decision_id": decision.decision_id,
            "decision_recomendada": plan["accion"],
            "accion_tipo": plan["accion_tipo"],
            "hipotesis": decision.hipotesis,
            "metrica_objetivo": decision.metrica_objetivo,
            "criterio_exito": decision.criterio_exito,
            "ventana_medicion": decision.ventana_medicion,
            "nivel_autonomia": int(nivel.value),
            "requiere_aprobacion": decision.requiere_aprobacion,
            "riesgo": decision.riesgo,
            "aprendizajes_consultados": len(aprendizajes),
        }


class OrquestarAccionAprobada:
    """ORCHESTRATE (§6.5) — coordinate ONLY approved actions, via gated executor (R1)."""

    def __init__(self, ejecutor):
        self.ejecutor = ejecutor

    def __call__(self, decision: dict[str, Any], contexto: dict[str, Any]) -> dict[str, Any]:
        resultado = self.ejecutor.ejecutar(decision)
        contexto["orquestacion"] = resultado
        return {
            "accion_ejecutada": resultado.get("accion_ejecutada"),
            "bloqueada_razon": resultado.get("bloqueada_razon"),
            "nivel_autonomia": decision.get("nivel_autonomia"),
            "aprobador": resultado.get("aprobador") or decision.get("aprobador"),
        }


class VerificarResultado:
    """VERIFY (§6.6) — measure whether the action moved the metric (R7)."""

    def __init__(self, verificador):
        self.verificador = verificador

    def __call__(self, decision: dict[str, Any], contexto: dict[str, Any]) -> dict[str, Any]:
        verif = self.verificador.verificar(decision)
        contexto["verificacion"] = verif
        return {
            "hipotesis_sostuvo": verif.get("hipotesis_sostuvo"),
            "estado_hipotesis": verif.get("estado_hipotesis"),
            "resultado": verif.get("resultado"),
        }


class RegistrarAprendizaje:
    """LEARN (§6.7) — close the loop: write learning + move to the Ledger (R8)."""

    def __init__(self, aprendiz):
        self.aprendiz = aprendiz

    def __call__(self, decision: dict[str, Any], contexto: dict[str, Any]) -> dict[str, Any]:
        verif = contexto.get("verificacion", {})
        res = self.aprendiz.aprender(decision, verif)
        return {
            "aprendizaje": res.get("aprendizaje"),
            "siguiente_movimiento": res.get("siguiente_movimiento"),
        }
