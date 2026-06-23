"""Superloop domain entities & value objects (SUPERLOOP.md §4.2, §10, §11)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .enums import (
    EstadoAprobacion,
    EstadoComercial,
    EstadoOperativo,
    EtiquetaAfirmacion,
    NivelAutonomia,
    SiguienteMovimiento,
)


@dataclass(frozen=True)
class Afirmacion:
    """R3 — a fact/inference/assumption/question, always labeled."""
    texto: str
    etiqueta: EtiquetaAfirmacion

    def to_dict(self) -> dict[str, str]:
        return {"texto": self.texto, "etiqueta": self.etiqueta.value}


@dataclass
class Producto:
    """Measurable business unit (§2). Subject of the loop.

    `kind` is "repo" (a scanned repository) or "supervisor" (a live action type).
    `source_ref` is the repo_url or the action_type id respectively.
    """
    producto_id: str
    nombre: str
    kind: str = "repo"
    owner: str | None = None
    proposito: str | None = None
    cliente_ideal: str | None = None
    modelo_ingresos: str | None = None
    expected_business_outcome: dict[str, Any] = field(default_factory=dict)
    source_ref: str | None = None
    tenant_id: str | None = None


@dataclass
class Snapshot:
    """§6.1 — output of OBSERVE."""
    producto_id: str
    fecha: str
    fuentes_consultadas: list[str] = field(default_factory=list)
    fuentes_inaccesibles: list[str] = field(default_factory=list)
    datos_faltantes: list[str] = field(default_factory=list)
    kpis: dict[str, Any] = field(default_factory=dict)
    afirmaciones: list[Afirmacion] = field(default_factory=list)


@dataclass
class Diagnostico:
    """§6.2 — output of DIAGNOSE."""
    producto_id: str
    estado_operativo: EstadoOperativo
    estado_comercial: EstadoComercial
    confianza: float
    metrica_principal: str | None
    kpis: dict[str, Any] = field(default_factory=dict)
    anomalias: list[str] = field(default_factory=list)
    riesgos: list[str] = field(default_factory=list)
    oportunidades: list[str] = field(default_factory=list)
    afirmaciones: list[Afirmacion] = field(default_factory=list)


@dataclass
class DecisionRecomendada:
    """§6.3 / §11 — approvable decision with backing (R6)."""
    decision_id: str
    producto_id: str
    fecha: str
    fase_origen: str
    decision_recomendada: str
    hipotesis: str
    metrica_objetivo: str
    criterio_exito: str
    ventana_medicion: str
    nivel_autonomia: NivelAutonomia
    accion_tipo: str = "observe"  # promote_policy | guard_stub | observe — drives ORCHESTRATE
    segmento: str | None = None
    impacto_esperado: str | None = None
    esfuerzo_estimado: str | None = None
    riesgo: str | None = None
    razonamiento: str | None = None
    opciones_consideradas: list[dict[str, Any]] = field(default_factory=list)
    datos_usados: dict[str, Any] = field(default_factory=dict)
    afirmaciones: list[Afirmacion] = field(default_factory=list)
    estado_aprobacion: EstadoAprobacion = EstadoAprobacion.PENDIENTE
    aprobador: str | None = None
    accion_ejecutada: str | None = None
    resultado: str | None = None
    aprendizaje: str | None = None
    siguiente_movimiento: SiguienteMovimiento | None = None
    ciclo_id: str | None = None

    @property
    def requiere_aprobacion(self) -> bool:
        return self.nivel_autonomia.requiere_aprobacion_humana

    def to_ledger_row(self) -> dict[str, Any]:
        """Flatten the decision to the §11 ledger schema (JSON where needed)."""
        return {
            "decision_id": self.decision_id,
            "producto_id": self.producto_id,
            "fecha": self.fecha,
            "fase_origen": self.fase_origen,
            "decision_recomendada": self.decision_recomendada,
            "accion_tipo": self.accion_tipo,
            "opciones_consideradas": self.opciones_consideradas,
            "razonamiento": self.razonamiento,
            "datos_usados": self.datos_usados,
            "afirmaciones": [a.to_dict() for a in self.afirmaciones],
            "hipotesis": self.hipotesis,
            "metrica_objetivo": self.metrica_objetivo,
            "segmento": self.segmento,
            "impacto_esperado": self.impacto_esperado,
            "esfuerzo_estimado": self.esfuerzo_estimado,
            "riesgo": self.riesgo,
            "nivel_autonomia": int(self.nivel_autonomia.value),
            "criterio_exito": self.criterio_exito,
            "ventana_medicion": self.ventana_medicion,
            "aprobador": self.aprobador,
            "estado_aprobacion": self.estado_aprobacion.value,
            "accion_ejecutada": self.accion_ejecutada,
            "resultado": self.resultado,
            "aprendizaje": self.aprendizaje,
            "siguiente_movimiento": (
                self.siguiente_movimiento.value if self.siguiente_movimiento else None
            ),
            "ciclo_id": self.ciclo_id,
        }

    def to_json_blob(self) -> str:
        return json.dumps(self.to_ledger_row(), default=str)


@dataclass
class Aprendizaje:
    """§6.7 — what a cycle learned; feeds the next DECIDE (R8)."""
    producto_id: str
    hipotesis: str
    resultado: str
    aprendizaje: str
    siguiente_movimiento: SiguienteMovimiento
    fecha: str


@dataclass
class RegistroCanonicoEntry:
    """§10 — current state of a product (one row)."""
    producto_id: str
    kind: str = "repo"
    nombre: str | None = None
    estado_operativo: str | None = None
    estado_comercial: str | None = None
    confianza_estado: float | None = None
    metrica_principal: str | None = None
    kpis: dict[str, Any] = field(default_factory=dict)
    afirmaciones: list[dict[str, Any]] = field(default_factory=list)
    hipotesis_vigente: str | None = None
    decision_recomendada_ref: str | None = None
    estado_aprobacion: str = "pendiente"
    proxima_mejor_accion: str | None = None
    ultimo_ciclo: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
