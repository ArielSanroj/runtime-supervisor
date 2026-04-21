"""Nivel 3 (opt-in): combo state tracking — STUB.

Planned behavior: each scan writes `runtime-supervisor/combos/state.yaml`
recording the status of every detected combo (open / in-progress / resolved).
Subsequent scans suppress already-resolved combos from the report (as long
as the evidence of the resolution — policy promoted + stubs present — is
still intact).

Schema (when implemented):

    combos:
      voice-clone-plus-outbound-call:
        status: resolved
        resolved_at: "2026-04-22T10:30:00Z"
        resolved_by: "alice@corp.com"
        evidence:
          policy_active: "tool_use.voice-clone-plus-outbound-call.v1"
          stubs_applied:
            - "src/agents/voice.ts"
            - "src/agents/tts.ts"
        notes: "Allowlist has 12 numbers, shadowed 2 weeks with 0 false positives."
      llm-plus-shell-exec:
        status: open

Why stubbed: requires (a) reliable detection of "policy is active" across
DB + YAML, (b) diffing stub-template vs actual-source to confirm wrapping,
(c) CLI verb `ac combos resolve <combo-id>` to record human decisions.

Until this ships, every scan re-reports the same combos. That's fine for
Nivel 1 (playbooks are idempotent), just noisier.

To enable when ready:
  1. Implement `load()`, `save()`, `mark_resolved()`, `filter_reported()`.
  2. Wire into `generator.py` so already-resolved combos drop out of the report.
  3. Add `ac combos` CLI subcommand for human interaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Status = Literal["open", "in-progress", "resolved"]


@dataclass(frozen=True)
class ComboState:
    combo_id: str
    status: Status = "open"
    resolved_at: str | None = None
    resolved_by: str | None = None


def load(state_path: Path) -> dict[str, ComboState]:
    """Stub — returns empty dict. Real impl will parse state.yaml."""
    return {}


def save(states: dict[str, ComboState], state_path: Path) -> None:
    """Stub — no-op. Real impl will write yaml."""
    pass


def mark_resolved(combo_id: str, state_path: Path, *, by: str, notes: str = "") -> None:
    """Stub — no-op. Planned verb: `ac combos resolve voice-clone-plus-outbound-call`."""
    raise NotImplementedError(
        "Combo state tracking is Nivel 3 (opt-in) and not yet implemented. "
        "Until it ships, each scan re-reports the same combos. That's fine — "
        "the playbooks are idempotent, just noisier."
    )


def filter_reported(all_combos: list, states: dict[str, ComboState]) -> list:
    """Stub — returns all_combos unchanged. Real impl will drop `resolved` combos
    where the resolution evidence is still intact."""
    return all_combos


def explain() -> str:
    """Describe Nivel 3 to the user."""
    return (
        "Nivel 3 — state tracking\n"
        "========================\n"
        "Marca combos como open / in-progress / resolved. Scans sucesivos no\n"
        "reportan combos ya resueltos (si la evidencia — policy activa + stubs\n"
        "deployados — sigue intacta). Convierte el reporte en un tracker de\n"
        "progreso en vez de una alerta repetida.\n"
        "\n"
        "Estado actual: stub. Cada scan re-reporta los mismos combos."
    )
