"""Superloop domain rules — pure business logic (SUPERLOOP.md §4.2, §8).

No IO. They operate on KPI/signal dicts and return classifications, anomalies
and the next move. Tailored to vibefixing's security domain: the "business
outcome" of a repo or a supervisor is *risk reduced*, and user-facing strings
are English (CLAUDE.md product-voice rule).
"""
from __future__ import annotations

from typing import Any

from .enums import EstadoComercial, EstadoOperativo, NivelAutonomia, SiguienteMovimiento

# Tunables — kept here so the thresholds are auditable in one place.
PRIORITY_RISK_THRESHOLD = 1      # >= this many priority findings = real unguarded risk
REVIEW_BACKLOG_THRESHOLD = 5     # pending review items that make a supervisor "needs attention"
STALE_DAYS = 45                  # no signal for this long = dormant
ABANDONED_DAYS = 180


def _num(d: dict[str, Any], key: str, default: float | None = None) -> float | None:
    v = d.get(key, default)
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# §8.1 — operational state (usage health). Generic over repos & supervisors.
# ---------------------------------------------------------------------------
def clasificar_estado_operativo(senales: dict[str, Any]) -> tuple[EstadoOperativo, float]:
    dias = _num(senales, "dias_desde_ultimo_uso")
    delta = _num(senales, "actividad_delta_pct")
    activos = _num(senales, "actividad_actual")

    if dias is None and delta is None and activos is None:
        return EstadoOperativo.DESCONOCIDO, 0.2
    if dias is not None and dias > ABANDONED_DAYS and (activos in (None, 0)):
        return EstadoOperativo.ABANDONADO, 0.8
    if dias is not None and dias > STALE_DAYS and (activos in (None, 0)):
        return EstadoOperativo.DORMIDO, 0.75
    if delta is not None and delta > 20:
        return EstadoOperativo.CRECIENDO, 0.75
    if delta is not None and -10 <= delta <= 10:
        return EstadoOperativo.ESTANCADO, 0.6
    if activos is not None and activos > 0:
        return EstadoOperativo.SALUDABLE, 0.6
    return EstadoOperativo.ESTANCADO, 0.4


# ---------------------------------------------------------------------------
# §8.2 — risk posture (the "commercial opportunity" axis, security-flavored).
# ---------------------------------------------------------------------------
def clasificar_estado_comercial(senales: dict[str, Any]) -> tuple[EstadoComercial, float]:
    riesgo = _num(senales, "risk_count", 0) or 0
    riesgo_delta = _num(senales, "risk_delta")          # >0 = regressing
    policy_shadow = bool(senales.get("policy_shadow"))
    actividad = _num(senales, "actividad_actual", 0) or 0
    dias = _num(senales, "dias_desde_ultimo_uso")

    # Regressing: risk went up since the previous observation → protect.
    if riesgo_delta is not None and riesgo_delta > 0 and riesgo > 0:
        return EstadoComercial.DEFENDER, 0.7
    # Dormant unit that still carries known risk → wake it up.
    if dias is not None and dias > STALE_DAYS and riesgo >= PRIORITY_RISK_THRESHOLD:
        return EstadoComercial.REACTIVAR, 0.65
    # Material unguarded risk worth fixing now.
    if riesgo >= PRIORITY_RISK_THRESHOLD:
        return EstadoComercial.ALTA_OPORTUNIDAD, 0.7
    # In use, guarded-but-shadow, low residual risk → tune/enforce.
    if policy_shadow and actividad > 0:
        return EstadoComercial.OPTIMIZAR, 0.6
    # In use with an enforcing policy and no residual risk → nothing to do.
    if riesgo == 0 and actividad > 0 and (riesgo_delta in (None, 0)):
        return EstadoComercial.CERRAR, 0.55
    # No activity / no signal — don't fake certainty (R3 / §7).
    return EstadoComercial.DESCONOCIDO, 0.3


def detectar_anomalias(senales: dict[str, Any]) -> list[str]:
    """§6.2 — security triggers (§15) detected in the signals."""
    out: list[str] = []
    riesgo_delta = _num(senales, "risk_delta")
    backlog = _num(senales, "review_backlog")
    deny_rate = _num(senales, "deny_rate")
    dias = _num(senales, "dias_desde_ultimo_uso")

    if riesgo_delta is not None and riesgo_delta > 0:
        out.append("risk_findings_increased")
    if senales.get("policy_shadow"):
        out.append("policy_still_in_shadow")
    if backlog is not None and backlog >= REVIEW_BACKLOG_THRESHOLD:
        out.append("review_backlog_growing")
    if dias is not None and dias > STALE_DAYS:
        out.append("stale_scan")
    if deny_rate is not None and deny_rate >= 0.5:
        out.append("high_deny_rate")
    return out


def metrica_principal(kind: str, senales: dict[str, Any]) -> str:
    if senales.get("metrica_principal"):
        return str(senales["metrica_principal"])
    return "priority_findings" if kind == "repo" else "review_backlog"


# ---------------------------------------------------------------------------
# §6.3 — next best action. Returns the full plan (English) + autonomy + accion_tipo.
# accion_tipo drives the ORCHESTRATE executor: guard_stub | promote_policy | observe.
# ---------------------------------------------------------------------------
def plan_siguiente_accion(
    kind: str,
    estado_op: EstadoOperativo,
    estado_com: EstadoComercial,
    senales: dict[str, Any],
) -> dict[str, Any]:
    riesgo = int(_num(senales, "risk_count", 0) or 0)
    would_block = int(_num(senales, "would_block_in_shadow", 0) or 0)
    policy_shadow = bool(senales.get("policy_shadow"))

    # Supervisor with a still-shadow policy AND something it would actually block
    # → enforcing it changes what gets blocked in production: external action,
    # Level 3, human gate (R1). Never recommend "promote" with nothing to enforce.
    if (kind == "supervisor" and policy_shadow and (would_block > 0 or riesgo > 0)
            and estado_com in (
                EstadoComercial.OPTIMIZAR, EstadoComercial.ALTA_OPORTUNIDAD,
                EstadoComercial.DEFENDER,
            )):
        return {
            "accion": "Promote the shadow policy to enforce so risky calls are actually blocked.",
            "accion_tipo": "promote_policy",
            "nivel": NivelAutonomia.EXTERNAL_ACTION,
            "hipotesis": "The policy already flags the right calls in shadow; enforcing it stops them without breaking legit traffic.",
            "metrica": "would_block_in_shadow",
            "criterio_exito": "deny/review acts on the shadow-flagged calls with no spike in human-approved reversals over 14 days",
            "riesgo": "alto",
        }

    # Repo carrying unguarded priority risk → draft a guard wrapper for review.
    if estado_com in (EstadoComercial.ALTA_OPORTUNIDAD, EstadoComercial.DEFENDER) and riesgo > 0:
        verb = "Re-draft" if estado_com == EstadoComercial.DEFENDER else "Draft"
        return {
            "accion": (f"{verb} a guard wrapper around the {riesgo} priority finding(s) "
                       f"and open it for review before anything ships."),
            "accion_tipo": "guard_stub",
            "nivel": NivelAutonomia.DRAFT,
            "hipotesis": "Wrapping the risky call sites with a supervised guard removes the unguarded path without a rewrite.",
            "metrica": "priority_findings",
            "criterio_exito": "priority_findings drops on the next scan after the guard is merged (14-day window)",
            "riesgo": "medio",
        }

    # Dormant unit with known risk → wake it up with a fresh scan + triage.
    if estado_com == EstadoComercial.REACTIVAR:
        return {
            "accion": "Re-scan this dormant repo and triage the findings before they drift further.",
            "accion_tipo": "guard_stub",
            "nivel": NivelAutonomia.DRAFT,
            "hipotesis": "A fresh scan surfaces what changed while the repo went quiet so we guard the right thing.",
            "metrica": "priority_findings",
            "criterio_exito": "a fresh scan exists and its priority findings are triaged within 14 days",
            "riesgo": "medio",
        }

    if estado_com == EstadoComercial.OPTIMIZAR:
        return {
            "accion": "Tune the policy thresholds so it catches the real risk without noisy reviews.",
            "accion_tipo": "observe",
            "nivel": NivelAutonomia.DRAFT,
            "hipotesis": "Tighter thresholds cut review noise while keeping the deny rate on genuinely risky calls.",
            "metrica": "review_backlog",
            "criterio_exito": "review_backlog trends down without losing true denies over 14 days",
            "riesgo": "bajo",
        }

    # Nothing material to act on — keep observing (Level 0).
    return {
        "accion": "No unguarded risk worth acting on right now — keep watching for regressions.",
        "accion_tipo": "observe",
        "nivel": NivelAutonomia.READ_ONLY,
        "hipotesis": "The unit is guarded/clean; the loop only needs to catch a future regression.",
        "metrica": metrica_principal(kind, senales),
        "criterio_exito": "no new priority risk appears before the next cycle",
        "riesgo": "bajo",
    }


def determinar_scale_iterate_hold_kill(
    hipotesis_sostuvo: bool | None,
    criterio_cumplido: bool | None,
    datos_suficientes: bool,
) -> SiguienteMovimiento:
    """§6.7 — move after VERIFY."""
    if not datos_suficientes:
        return SiguienteMovimiento.HOLD
    if criterio_cumplido and hipotesis_sostuvo:
        return SiguienteMovimiento.SCALE
    if criterio_cumplido or hipotesis_sostuvo:
        return SiguienteMovimiento.ITERATE
    return SiguienteMovimiento.KILL
