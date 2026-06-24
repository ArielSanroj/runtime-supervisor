"""Registro Canónico adapter (SUPERLOOP.md §10) — SuperloopProduct table (R4).

Single source of truth for each unit's current state. History is stacked into
the `historial` JSON list; writes never erase it.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import SuperloopProduct
from ..application.ports import RegistroCanonico
from ..domain.entities import Producto, RegistroCanonicoEntry

_MAX_HISTORY = 50


class RegistroCanonicoPg(RegistroCanonico):
    def __init__(self, db: Session, tenant_id: str | None):
        self.db = db
        self.tenant_id = tenant_id

    def _row(self, producto_id: str) -> SuperloopProduct | None:
        return self.db.get(SuperloopProduct, producto_id)

    def upsert(self, entry: RegistroCanonicoEntry) -> None:
        row = self._row(entry.producto_id)
        if row is None:
            row = SuperloopProduct(
                producto_id=entry.producto_id,
                tenant_id=self.tenant_id,
                kind=entry.kind,
                nombre=entry.nombre or entry.producto_id,
                kpis={},
                afirmaciones=[],
                ultimo_ciclo={},
                historial=[],
            )
            self.db.add(row)
        # Only overwrite fields the caller actually provided (partial upserts).
        if entry.nombre is not None:
            row.nombre = entry.nombre
        row.kind = entry.kind or row.kind
        if entry.estado_operativo is not None:
            row.estado_operativo = entry.estado_operativo
        if entry.estado_comercial is not None:
            row.estado_comercial = entry.estado_comercial
        if entry.confianza_estado is not None:
            row.confianza_estado = entry.confianza_estado
        if entry.metrica_principal is not None:
            row.metrica_principal = entry.metrica_principal
        if entry.kpis:
            row.kpis = entry.kpis
        if entry.afirmaciones:
            row.afirmaciones = entry.afirmaciones
        if entry.hipotesis_vigente is not None:
            row.hipotesis_vigente = entry.hipotesis_vigente
        if entry.decision_recomendada_ref is not None:
            row.decision_recomendada_ref = entry.decision_recomendada_ref
        if entry.estado_aprobacion:
            row.estado_aprobacion = entry.estado_aprobacion
        if entry.proxima_mejor_accion is not None:
            row.proxima_mejor_accion = entry.proxima_mejor_accion
        if entry.ultimo_ciclo:
            row.ultimo_ciclo = entry.ultimo_ciclo
        row.updated_at = datetime.now(UTC)
        self.db.flush()

    def get(self, producto_id: str) -> RegistroCanonicoEntry | None:
        row = self._row(producto_id)
        if row is None:
            return None
        return RegistroCanonicoEntry(
            producto_id=row.producto_id,
            kind=row.kind,
            nombre=row.nombre,
            estado_operativo=row.estado_operativo,
            estado_comercial=row.estado_comercial,
            confianza_estado=row.confianza_estado,
            metrica_principal=row.metrica_principal,
            kpis=row.kpis or {},
            afirmaciones=row.afirmaciones or [],
            hipotesis_vigente=row.hipotesis_vigente,
            decision_recomendada_ref=row.decision_recomendada_ref,
            estado_aprobacion=row.estado_aprobacion,
            proxima_mejor_accion=row.proxima_mejor_accion,
            ultimo_ciclo=row.ultimo_ciclo or {},
        )

    def append_history(self, producto_id: str, fase: str, snapshot: dict[str, Any],
                       ciclo_id: str | None = None) -> None:
        row = self._row(producto_id)
        if row is None:
            return
        # JSON columns need reassignment to be detected as dirty by the ORM.
        hist = list(row.historial or [])
        hist.append({"fase": fase, "ciclo_id": ciclo_id, "snapshot": snapshot,
                     "at": datetime.now(UTC).isoformat()})
        row.historial = hist[-_MAX_HISTORY:]
        self.db.flush()

    def list_productos(self) -> list[Producto]:
        rows = self.db.execute(
            select(SuperloopProduct).where(SuperloopProduct.tenant_id == self.tenant_id)
        ).scalars().all()
        return [
            Producto(producto_id=r.producto_id, nombre=r.nombre, kind=r.kind,
                     source_ref=r.source_ref, tenant_id=r.tenant_id)
            for r in rows
        ]
