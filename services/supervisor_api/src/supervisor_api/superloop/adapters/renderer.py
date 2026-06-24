"""Output contract renderer (SUPERLOOP.md §12, §18) — Business Card + Evidence Pack.

User-facing, so English product voice (CLAUDE.md). Everything is derived from the
loop's records — no hardcoded numbers.
"""
from __future__ import annotations

from typing import Any

from ..application.state_machine import CicloResultado
from ..domain.entities import Producto


def build_cards(
    producto: Producto,
    resultado: CicloResultado | None,
    gate: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    if error or resultado is None:
        return {
            "producto": producto.nombre,
            "producto_id": producto.producto_id,
            "kind": producto.kind,
            "error": error,
            "business_card": None,
            "evidence_pack": None,
        }

    diag = resultado.registros.get("diagnose", {})
    decide = resultado.registros.get("decide", {})
    observe = resultado.registros.get("observe", {})
    gate = gate or {}

    business_card = {
        "producto": producto.nombre,
        "producto_id": producto.producto_id,
        "kind": producto.kind,
        "estado_operativo": diag.get("estado_operativo"),
        "estado_comercial": diag.get("estado_comercial"),
        "confianza": diag.get("confianza"),
        "problema_principal": (diag.get("anomalias") or ["—"])[0],
        "metrica_principal": diag.get("metrica_principal"),
        "decision_recomendada": decide.get("decision_recomendada"),
        "accion_tipo": decide.get("accion_tipo"),
        "impacto_esperado": "medium",
        "riesgo": decide.get("riesgo"),
        "nivel_autonomia": decide.get("nivel_autonomia"),
        "requiere_aprobacion": decide.get("requiere_aprobacion"),
        "proxima_accion": decide.get("decision_recomendada"),
        "decision_id": decide.get("decision_id"),
        "estado_aprobacion": gate.get("estado", "n/a"),
        "review_item_id": gate.get("review_item_id"),
    }
    evidence_pack = {
        "resumen_ejecutivo": (
            f"{producto.nombre}: usage={diag.get('estado_operativo')}, "
            f"risk_posture={diag.get('estado_comercial')}."
        ),
        "afirmaciones": diag.get("afirmaciones", []),
        "kpis": diag.get("kpis", {}),
        "hipotesis": decide.get("hipotesis"),
        "plan_de_accion": {
            "metrica_objetivo": decide.get("metrica_objetivo"),
            "criterio_exito": decide.get("criterio_exito"),
            "ventana_medicion": decide.get("ventana_medicion"),
            "accion_tipo": decide.get("accion_tipo"),
        },
        "fuentes_consultadas": observe.get("fuentes_consultadas", []),
        "fuentes_inaccesibles": observe.get("fuentes_inaccesibles", []),
        "decision_ledger_ref": decide.get("decision_id"),
        "registro_canonico_ref": producto.producto_id,
        "aprendizajes_consultados": decide.get("aprendizajes_consultados", 0),
        "detenido_en": resultado.detenido_en,
        "motivo_detencion": resultado.motivo_detencion,
        "siguiente_movimiento": (
            "HOLD (pending human approval)" if business_card["requiere_aprobacion"]
            else "auto (no human gate required)"
        ),
    }
    return {
        "producto": producto.nombre,
        "producto_id": producto.producto_id,
        "kind": producto.kind,
        "error": None,
        "business_card": business_card,
        "evidence_pack": evidence_pack,
    }
