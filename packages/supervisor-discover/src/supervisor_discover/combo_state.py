"""Level 3 — combo state tracking.

Every detected combo can be in one of 3 states: `open` (default on detection),
`in-progress` (the team is working on it), or `resolved` (the playbook has
been applied and verified). Resolved combos are suppressed from the next
scan so the report becomes a progress tracker rather than the same catalog
repeated every run.

State file: `runtime-supervisor/combos.state.yaml` (lives alongside
`combos/` and `policies/`). Format:

    version: 1
    combos:
      voice-clone-plus-outbound-call:
        status: resolved
        resolved_at: "2026-04-21T18:30:00Z"
        resolved_by: "ariel@clio.com"
        note: "Allowlist of 12 numbers, 2 weeks shadow with zero FPs."
      llm-plus-shell-exec:
        status: in-progress
        note: "Applying the command allowlist."

**Trust model:** we trust that the human only marks `resolved` once the
playbook has actually been applied. No evidence verification (policy
promoted, wraps in code) in this version. If a user removes the wrap
after marking resolved, the scan won't re-detect it until they run
`combos reopen <id>`. A future version can add evidence checks.

CLI interaction (ver `cli._handle_combos`):
    supervisor-discover combos                    # list status
    supervisor-discover combos resolve <id>       # mark resolved
    supervisor-discover combos reopen <id>        # revert a open
    supervisor-discover combos clear              # delete state file
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml

Status = Literal["open", "in-progress", "resolved"]

# Path relativo al out_dir (runtime-supervisor/). Usado por generator.py y CLI.
STATE_FILENAME = "combos.state.yaml"

_STATE_VERSION = 1


@dataclass
class ComboState:
    combo_id: str
    status: Status = "open"
    resolved_at: str | None = None
    resolved_by: str | None = None
    note: str = ""

    def to_dict(self) -> dict:
        """YAML dump — omit None fields for readability."""
        d: dict = {"status": self.status}
        if self.resolved_at:
            d["resolved_at"] = self.resolved_at
        if self.resolved_by:
            d["resolved_by"] = self.resolved_by
        if self.note:
            d["note"] = self.note
        return d


def state_path_for(out_dir: Path) -> Path:
    """Canonical location of the state file inside runtime-supervisor/."""
    return out_dir / STATE_FILENAME


def load(state_path: Path) -> dict[str, ComboState]:
    """Parse combos.state.yaml into {combo_id: ComboState}. Missing file or
    malformed YAML both return an empty dict — the caller treats that as
    "no tracking active"."""
    if not state_path.exists():
        return {}
    try:
        raw = yaml.safe_load(state_path.read_text()) or {}
    except yaml.YAMLError:
        return {}
    combos_map = raw.get("combos") or {}
    out: dict[str, ComboState] = {}
    for combo_id, data in combos_map.items():
        if not isinstance(data, dict):
            continue
        status = data.get("status", "open")
        if status not in ("open", "in-progress", "resolved"):
            status = "open"
        out[combo_id] = ComboState(
            combo_id=combo_id,
            status=status,
            resolved_at=data.get("resolved_at"),
            resolved_by=data.get("resolved_by"),
            note=data.get("note", "") or "",
        )
    return out


def save(states: dict[str, ComboState], state_path: Path) -> None:
    """Write the state map as YAML. Creates parent dir if needed. Stable
    sort by combo_id so diffs are clean."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": _STATE_VERSION,
        "combos": {
            cid: states[cid].to_dict()
            for cid in sorted(states.keys())
        },
    }
    state_path.write_text(
        "# runtime-supervisor combo state — managed by `supervisor-discover combos`\n"
        "# Marca un combo como resolved con: supervisor-discover combos resolve <id>\n"
        "#\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mark_resolved(
    combo_id: str,
    state_path: Path,
    *,
    by: str | None = None,
    note: str = "",
) -> ComboState:
    """Mark a combo as resolved and persist. Returns the new state."""
    states = load(state_path)
    states[combo_id] = ComboState(
        combo_id=combo_id,
        status="resolved",
        resolved_at=_now_iso(),
        resolved_by=by,
        note=note,
    )
    save(states, state_path)
    return states[combo_id]


def mark_in_progress(combo_id: str, state_path: Path, *, note: str = "") -> ComboState:
    """Mark as in-progress (working on it, don't suppress from reports)."""
    states = load(state_path)
    states[combo_id] = ComboState(
        combo_id=combo_id,
        status="in-progress",
        note=note,
    )
    save(states, state_path)
    return states[combo_id]


def mark_open(combo_id: str, state_path: Path) -> ComboState:
    """Revert a combo to open — re-enables its reporting in scans."""
    states = load(state_path)
    states[combo_id] = ComboState(combo_id=combo_id, status="open")
    save(states, state_path)
    return states[combo_id]


def clear(state_path: Path) -> bool:
    """Delete the state file. Returns True if a file was removed."""
    if state_path.exists():
        state_path.unlink()
        return True
    return False


def filter_reported(
    all_combos: list,
    states: dict[str, ComboState],
    *,
    include_resolved: bool = False,
) -> list:
    """Drop resolved combos from the list passed to the report renderers.

    `all_combos` is a list of Combo objects (from combos.detect_combos).
    Returns a filtered list — `resolved` entries are dropped unless
    `include_resolved=True` (for --show-resolved CLI flag).

    `in-progress` and `open` are never filtered — in-progress appears in
    the report with a note, open is the default detected state.
    """
    if include_resolved or not states:
        return all_combos
    resolved_ids = {cid for cid, s in states.items() if s.status == "resolved"}
    if not resolved_ids:
        return all_combos
    return [c for c in all_combos if c.id not in resolved_ids]


def explain() -> str:
    """Short description for `supervisor-discover combos --help` and
    for the interactive prompt when user picks option [3]."""
    return (
        "Level 3 — state tracking\n"
        "========================\n"
        "Mark combos as open / in-progress / resolved. Resolved combos\n"
        "disappear from the next scan so the report becomes a progress\n"
        "tracker, not the same catalog repeated every run.\n"
        "\n"
        "Verbs:\n"
        "  supervisor-discover combos                    # list status\n"
        "  supervisor-discover combos resolve <id>       # mark resolved\n"
        "  supervisor-discover combos reopen <id>        # back to open\n"
        "  supervisor-discover combos clear              # wipe state file\n"
        "\n"
        "State file: runtime-supervisor/combos.state.yaml (commiteable)."
    )
