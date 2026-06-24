"""Superloop ports (SUPERLOOP.md §4.2) — interfaces the application needs.

Outbound: what the application requires from the outside world. Concrete adapters
implement them in `superloop/adapters/`. The domain knows none of these.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..domain.entities import (
    Aprendizaje,
    DecisionRecomendada,
    Producto,
    RegistroCanonicoEntry,
    Snapshot,
)


class FuenteDeDatos(ABC):
    """Reads business signals (KPIs, usage). Read-only (R2)."""

    @abstractmethod
    def observar(self, producto: Producto) -> Snapshot: ...


class RegistroCanonico(ABC):
    """§10 — current state per product. Single source of truth (R4)."""

    @abstractmethod
    def upsert(self, entry: RegistroCanonicoEntry) -> None: ...

    @abstractmethod
    def get(self, producto_id: str) -> RegistroCanonicoEntry | None: ...

    @abstractmethod
    def append_history(self, producto_id: str, fase: str, snapshot: dict[str, Any],
                       ciclo_id: str | None = None) -> None: ...

    @abstractmethod
    def list_productos(self) -> list[Producto]: ...


class DecisionLedger(ABC):
    """§11 — append-only log of decisions/approvals/results/learnings."""

    @abstractmethod
    def registrar(self, decision: DecisionRecomendada) -> str: ...

    @abstractmethod
    def get(self, decision_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def ultimos_aprendizajes(self, producto_id: str, limit: int = 5) -> list[Aprendizaje]:
        """R8 — DECIDE consults this before deciding."""
        ...

    @abstractmethod
    def actualizar_aprobacion(self, decision_id: str, estado: str,
                              aprobador: str | None) -> None: ...


class CanalDePropuesta(ABC):
    """Presents a decision to the human (Slack, email-draft, stdout)."""

    @abstractmethod
    def proponer(self, business_card: dict[str, Any], evidence_pack: dict[str, Any]) -> None: ...


class EjecutorDeAcciones(ABC):
    """ORCHESTRATE — ALWAYS gated (R1). Only acts with a registered approval."""

    @abstractmethod
    def ejecutar(self, decision: dict[str, Any]) -> dict[str, Any]: ...


class GateDeAprobacion(ABC):
    """R1 — opens/reads the human approval gate for Level >= 3 decisions."""

    @abstractmethod
    def solicitar(self, decision: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    def estado(self, decision: dict[str, Any]) -> dict[str, Any]: ...


class Verificador(ABC):
    """VERIFY — measures whether the action moved the metric (R7)."""

    @abstractmethod
    def verificar(self, decision: dict[str, Any]) -> dict[str, Any]: ...


class ProveedorDeTiempo(ABC):
    @abstractmethod
    def ahora(self) -> str: ...


class ProveedorDeIdentidad(ABC):
    @abstractmethod
    def nuevo_id(self, prefijo: str) -> str: ...
