"""Superloop "definition of done" per phase (SUPERLOOP.md §16) — pure predicates.

THIS is the single source of truth for "is the phase done?". Used by both the
state machine (R5: never advance without meeting a phase) and any enforcement
hooks (§20).

Each predicate takes a flat dict (a "phase record") and returns
(ok: bool, missing: list[str]). They work on dicts — not entities — so callers
can validate raw task JSON without instantiating the domain.

Also validates the hard rules:
  R3 — claims labeled HECHO/INFERENCIA/SUPUESTO/PREGUNTA
  R6 — every decision carries hypothesis + metric + success criterion + window
  R1 — every Level >= 3 action carries a registered human approver
"""
from __future__ import annotations

from typing import Any

ETIQUETAS_VALIDAS = {"HECHO", "INFERENCIA", "SUPUESTO", "PREGUNTA"}


def _afirmaciones_etiquetadas(afirmaciones: Any) -> tuple[bool, list[str]]:
    """R3 — every claim must carry a valid label."""
    faltantes: list[str] = []
    if not isinstance(afirmaciones, list):
        return False, ["afirmaciones is not a list"]
    for i, a in enumerate(afirmaciones):
        etiqueta = a.get("etiqueta") if isinstance(a, dict) else None
        if etiqueta not in ETIQUETAS_VALIDAS:
            faltantes.append(f"claim[{i}] missing valid label (R3): {etiqueta!r}")
    return (not faltantes), faltantes


def observe_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    faltan: list[str] = []
    if not reg.get("snapshot_fecha"):
        faltan.append("missing fresh snapshot")
    if not reg.get("fuentes_consultadas") and not reg.get("fuentes_inaccesibles"):
        faltan.append("no source consulted nor marked inaccessible")
    _, faltan_af = _afirmaciones_etiquetadas(reg.get("afirmaciones", []))
    faltan += faltan_af
    return (not faltan), faltan


def diagnose_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    faltan: list[str] = []
    if not reg.get("estado_operativo"):
        faltan.append("missing estado_operativo")
    if not reg.get("estado_comercial"):
        faltan.append("missing estado_comercial")
    if not reg.get("metrica_principal"):
        faltan.append("missing metrica_principal")
    _, faltan_af = _afirmaciones_etiquetadas(reg.get("afirmaciones", []))
    faltan += faltan_af
    return (not faltan), faltan


def decide_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    faltan: list[str] = []
    for campo in ("hipotesis", "metrica_objetivo", "criterio_exito", "ventana_medicion"):
        if not reg.get(campo):
            faltan.append(f"missing {campo} (R6)")
    if reg.get("nivel_autonomia") is None:
        faltan.append("missing nivel_autonomia")
    return (not faltan), faltan


def approve_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    """§16 APPROVE done + R1: approval resolved; no Level >= 3 action advances
    without a human approver."""
    faltan: list[str] = []
    estado = reg.get("estado_aprobacion")
    if estado not in ("aprobado", "rechazado", "requiere_cambios"):
        faltan.append("estado_aprobacion still pending (cannot advance)")
    nivel = reg.get("nivel_autonomia")
    try:
        nivel_i = int(nivel) if nivel is not None else 0
    except (TypeError, ValueError):
        nivel_i = 0
    if nivel_i >= 3 and estado == "aprobado" and not reg.get("aprobador"):
        faltan.append("Level >= 3 action approved without human approver (R1)")
    return (not faltan), faltan


def orchestrate_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    faltan: list[str] = []
    if not reg.get("accion_ejecutada") and not reg.get("bloqueada_razon"):
        faltan.append("action neither executed nor marked blocked")
    nivel = reg.get("nivel_autonomia")
    try:
        nivel_i = int(nivel) if nivel is not None else 0
    except (TypeError, ValueError):
        nivel_i = 0
    if nivel_i >= 3 and not reg.get("aprobador"):
        faltan.append("orchestrating Level >= 3 without human approver (R1)")
    return (not faltan), faltan


def verify_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    """§16 VERIFY done: gate evaluated against data, hypothesis held/failed/uncertain.

    'uncertain' is a VALID state (not the same as not recording it)."""
    faltan: list[str] = []
    estado = reg.get("estado_hipotesis")
    if estado not in ("sostuvo", "fallo", "incierta") and reg.get("hipotesis_sostuvo") is None:
        faltan.append("did not record whether hypothesis held/failed/uncertain")
    if not reg.get("resultado"):
        faltan.append("missing measured result")
    return (not faltan), faltan


def learn_done(reg: dict[str, Any]) -> tuple[bool, list[str]]:
    faltan: list[str] = []
    if reg.get("siguiente_movimiento") not in ("scale", "iterate", "hold", "kill"):
        faltan.append("siguiente_movimiento must be scale/iterate/hold/kill")
    if not reg.get("aprendizaje"):
        faltan.append("missing recorded learning (R8)")
    return (not faltan), faltan


PREDICADOS = {
    "observe": observe_done,
    "diagnose": diagnose_done,
    "decide": decide_done,
    "approve": approve_done,
    "orchestrate": orchestrate_done,
    "verify": verify_done,
    "learn": learn_done,
}


def fase_terminada(fase: str, reg: dict[str, Any]) -> tuple[bool, list[str]]:
    """Dispatcher: is `fase` done given its record `reg`?"""
    pred = PREDICADOS.get(fase)
    if pred is None:
        return False, [f"unknown phase: {fase!r}"]
    return pred(reg)
