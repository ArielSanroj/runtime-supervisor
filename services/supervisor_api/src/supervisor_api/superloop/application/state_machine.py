"""Superloop state machine (SUPERLOOP.md §6, §16) — loop orchestrator.

Advances OBSERVE → DIAGNOSE → DECIDE → APPROVE → ORCHESTRATE → VERIFY → LEARN
ONLY when the current phase meets its definition of done (R5). Any attempt to
skip an unfinished phase raises PhaseNotDone.

`detener_en` stops the machine before a phase — the read-only run (OBSERVE→DECIDE,
stop at APPROVE) sets it to "approve" so nothing gated runs before a human gate.
The full loop (post-approval) is driven separately via the facade's resume path.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..domain import phase_done
from ..domain.enums import Fase


class PhaseNotDone(Exception):
    """Tried to advance without meeting the phase's definition of done (R5)."""

    def __init__(self, fase: str, faltantes: list[str]):
        self.fase = fase
        self.faltantes = faltantes
        super().__init__(f"Phase '{fase}' not done: {'; '.join(faltantes)}")


@dataclass
class CicloResultado:
    """Result of one (partial) loop turn."""
    producto_id: str
    fase_alcanzada: str
    registros: dict[str, dict[str, Any]] = field(default_factory=dict)
    detenido_en: str | None = None
    motivo_detencion: str | None = None

    @property
    def registro_actual(self) -> dict[str, Any]:
        return self.registros.get(self.fase_alcanzada, {})


class SuperloopStateMachine:
    """Sequences the phases, validating each transition with phase_done (R5).

    `use_cases` is a dict phase->callable. Each callable takes (producto, contexto)
    and returns the flat "record" for that phase (the shape phase_done validates).
    The context accumulates prior records.
    """

    def __init__(self, use_cases: dict[str, Callable[[Any, dict], dict[str, Any]]],
                 detener_en: str | None = Fase.APPROVE.value):
        self.use_cases = use_cases
        self.detener_en = detener_en

    def run(self, producto: Any) -> CicloResultado:
        contexto: dict[str, Any] = {"registros": {}}
        resultado = CicloResultado(
            producto_id=getattr(producto, "producto_id", str(producto)),
            fase_alcanzada=Fase.OBSERVE.value,
        )

        for fase in Fase.orden():
            fase_val = fase.value

            if self.detener_en and fase_val == self.detener_en:
                resultado.detenido_en = fase_val
                resultado.motivo_detencion = (
                    f"Human gate: the loop stops at {fase_val} (R1)."
                )
                break

            use_case = self.use_cases.get(fase_val)
            if use_case is None:
                resultado.detenido_en = fase_val
                resultado.motivo_detencion = f"No use case for {fase_val} (not wired)."
                break

            registro = use_case(producto, contexto)
            contexto["registros"][fase_val] = registro
            resultado.registros[fase_val] = registro
            resultado.fase_alcanzada = fase_val

            ok, faltantes = phase_done.fase_terminada(fase_val, registro)
            if not ok:
                raise PhaseNotDone(fase_val, faltantes)

        return resultado
