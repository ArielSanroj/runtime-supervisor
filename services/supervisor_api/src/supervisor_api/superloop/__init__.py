"""Superloop — closed-loop business agent for vibefixing (SUPERLOOP.md).

OBSERVE → DIAGNOSE → DECIDE → APPROVE → ORCHESTRATE → VERIFY → LEARN → REPEAT
over two kinds of business unit (`Producto`): scanned **repos** and live
**supervisors** (action types). Hexagonal: `domain/` is pure, `application/`
holds the state machine + use cases, `adapters/` bind to the existing
SQLAlchemy models (Scan / Decision / ReviewItem / PolicyRecord / EvidenceEvent).

Entry point: `from supervisor_api.superloop.facade import SuperloopFacade`.
"""
from __future__ import annotations

from .facade import SuperloopFacade

__all__ = ["SuperloopFacade"]
