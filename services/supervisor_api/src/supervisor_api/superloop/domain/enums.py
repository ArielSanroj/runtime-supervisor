"""Superloop domain enums (SUPERLOOP.md §6, §8, §9, §3).

Faithful port of the cross-repo Superloop vocabulary. Internal identifiers stay
in the charter's language; everything user-facing is rendered to English by the
renderer adapter.
"""
from __future__ import annotations

from enum import Enum


class Fase(str, Enum):
    """Phases of the operating loop (§6)."""
    OBSERVE = "observe"
    DIAGNOSE = "diagnose"
    DECIDE = "decide"
    APPROVE = "approve"
    ORCHESTRATE = "orchestrate"
    VERIFY = "verify"
    LEARN = "learn"

    @classmethod
    def orden(cls) -> list["Fase"]:
        return [cls.OBSERVE, cls.DIAGNOSE, cls.DECIDE, cls.APPROVE,
                cls.ORCHESTRATE, cls.VERIFY, cls.LEARN]

    def siguiente(self) -> "Fase | None":
        orden = self.orden()
        i = orden.index(self)
        return orden[i + 1] if i + 1 < len(orden) else None


class EtiquetaAfirmacion(str, Enum):
    """R3 — every claim carries one of these labels."""
    HECHO = "HECHO"            # measured directly in data
    INFERENCIA = "INFERENCIA"  # reasonably deduced from data
    SUPUESTO = "SUPUESTO"      # assumed without sufficient evidence
    PREGUNTA = "PREGUNTA"      # needs human validation or more data


class EstadoOperativo(str, Enum):
    """§8.1 — usage health of the unit."""
    CRECIENDO = "creciendo"
    SALUDABLE = "saludable"
    ESTANCADO = "estancado"
    DORMIDO = "dormido"
    ABANDONADO = "abandonado"
    DESCONOCIDO = "desconocido"


class EstadoComercial(str, Enum):
    """§8.2 — business/risk opportunity of the unit.

    In vibefixing's security domain these read as risk posture:
      alta_oportunidad = high unguarded risk worth fixing now
      defender         = was guarded/clean, now regressing — protect it
      optimizar        = guarded but policy can be tuned
      reactivar        = dormant unit with known risk — wake it up
      cerrar           = no material risk / archived
    """
    ALTA_OPORTUNIDAD = "alta_oportunidad"
    DEFENDER = "defender"
    OPTIMIZAR = "optimizar"
    REACTIVAR = "reactivar"
    CERRAR = "cerrar"
    DESCONOCIDO = "desconocido"


class NivelAutonomia(int, Enum):
    """§9 — autonomy level by blast radius of the action."""
    READ_ONLY = 0
    DRAFT = 1
    INTERNAL_WRITE = 2
    EXTERNAL_ACTION = 3
    BUSINESS_CRITICAL = 4

    @property
    def requiere_aprobacion_humana(self) -> bool:
        """Level 3-4 always needs a human approver (R1)."""
        return self.value >= 3


class EstadoAprobacion(str, Enum):
    """§6.4 — outcome of the approval gate."""
    PENDIENTE = "pendiente"
    APROBADO = "aprobado"
    RECHAZADO = "rechazado"
    REQUIERE_CAMBIOS = "requiere_cambios"


class SiguienteMovimiento(str, Enum):
    """§6.7 — move after VERIFY."""
    SCALE = "scale"
    ITERATE = "iterate"
    HOLD = "hold"
    KILL = "kill"
