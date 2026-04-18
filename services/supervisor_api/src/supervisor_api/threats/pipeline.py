"""Threat pipeline — orchestrates detectors and returns an assessment."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from .detectors import ALL_DETECTORS, Signal

Level = str  # "none" | "info" | "warn" | "critical"

_LEVEL_ORDER = {"none": 0, "info": 1, "warn": 2, "critical": 3}


@dataclass(frozen=True)
class ThreatAssessment:
    level: Level
    signals: list[Signal] = field(default_factory=list)

    @property
    def is_blocking(self) -> bool:
        return self.level == "critical"

    @property
    def needs_review(self) -> bool:
        return self.level == "warn"


def _worst(levels: list[str]) -> str:
    if not levels:
        return "none"
    return max(levels, key=lambda level: _LEVEL_ORDER.get(level, 0))


def assess(
    payload: dict[str, Any],
    *,
    db: Session | None = None,
    integration_id: str | None = None,
) -> ThreatAssessment:
    """Run every detector and collapse their signals into an assessment."""
    ctx = {"db": db, "integration_id": integration_id}
    all_signals: list[Signal] = []
    for detector in ALL_DETECTORS:
        try:
            all_signals.extend(detector(payload, ctx))
        except Exception as e:
            # Never let a detector kill the pipeline; surface as info.
            all_signals.append(Signal(
                detector_id=getattr(detector, "__name__", "unknown"),
                owasp_ref="-", level="info",
                message=f"detector crashed: {e}", evidence={},
            ))
    return ThreatAssessment(level=_worst([s.level for s in all_signals]), signals=all_signals)
