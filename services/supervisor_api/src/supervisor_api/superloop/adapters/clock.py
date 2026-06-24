"""Time + identity providers (SUPERLOOP.md §4.2 outbound ports)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ..application.ports import ProveedorDeIdentidad, ProveedorDeTiempo


class TiempoUTC(ProveedorDeTiempo):
    def ahora(self) -> str:
        return datetime.now(UTC).isoformat()


class IdentidadUUID(ProveedorDeIdentidad):
    def nuevo_id(self, prefijo: str) -> str:
        return f"{prefijo}_{uuid.uuid4().hex[:12]}"
