"""Nivel 3 — combo state tracking.

Cubre:
- Roundtrip yaml: mark_resolved → save → load recupera el mismo status
- filter_reported: resolved se suprime, open/in-progress se mantienen
- include_resolved=True bypasses el filtro
- clear() borra el file
- Un combo re-marcado (resolve → reopen → resolve) termina en el último estado
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.combo_state import (
    ComboState,
    clear,
    filter_reported,
    load,
    mark_in_progress,
    mark_open,
    mark_resolved,
    save,
    state_path_for,
)
from supervisor_discover.combos import Combo


def _combo(cid: str, severity: str = "high") -> Combo:
    return Combo(
        id=cid,
        title=f"Combo {cid}",
        severity=severity,
        narrative="test narrative",
        evidence=["file.py:1"],
        mitigation="wrap it",
    )


def test_load_missing_file_returns_empty():
    assert load(Path("/nonexistent/combos.state.yaml")) == {}


def test_save_and_load_roundtrip(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    states = {
        "alpha": ComboState(combo_id="alpha", status="resolved",
                            resolved_at="2026-04-21T00:00:00Z",
                            resolved_by="test@x.com", note="done"),
        "beta": ComboState(combo_id="beta", status="open"),
    }
    save(states, sp)
    loaded = load(sp)
    assert set(loaded.keys()) == {"alpha", "beta"}
    assert loaded["alpha"].status == "resolved"
    assert loaded["alpha"].resolved_by == "test@x.com"
    assert loaded["alpha"].note == "done"
    assert loaded["beta"].status == "open"


def test_mark_resolved_persists_and_timestamps(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    state = mark_resolved("combo-a", sp, by="ariel@x.com", note="wrapped")
    assert state.status == "resolved"
    assert state.resolved_at is not None
    # Timestamp is ISO-ish (Z suffix)
    assert state.resolved_at.endswith("Z")
    # Persisted
    loaded = load(sp)
    assert loaded["combo-a"].status == "resolved"
    assert loaded["combo-a"].resolved_by == "ariel@x.com"
    assert loaded["combo-a"].note == "wrapped"


def test_filter_reported_drops_resolved_keeps_others(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    mark_resolved("combo-a", sp, note="done")
    mark_in_progress("combo-b", sp, note="working")
    states = load(sp)

    all_combos = [_combo("combo-a"), _combo("combo-b"), _combo("combo-c")]
    filtered = filter_reported(all_combos, states)
    ids = {c.id for c in filtered}
    # combo-a (resolved) is dropped; combo-b (in-progress) and combo-c (no state) stay
    assert ids == {"combo-b", "combo-c"}


def test_filter_reported_include_resolved_bypasses_filter(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    mark_resolved("combo-a", sp)
    states = load(sp)
    all_combos = [_combo("combo-a"), _combo("combo-b")]
    filtered = filter_reported(all_combos, states, include_resolved=True)
    assert {c.id for c in filtered} == {"combo-a", "combo-b"}


def test_filter_reported_without_states_returns_all_unchanged():
    all_combos = [_combo("combo-a"), _combo("combo-b")]
    assert filter_reported(all_combos, {}) == all_combos


def test_mark_open_revives_resolved_combo(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    mark_resolved("combo-a", sp, note="was done")
    mark_open("combo-a", sp)
    states = load(sp)
    assert states["combo-a"].status == "open"
    # Verify filter no longer drops it
    filtered = filter_reported([_combo("combo-a")], states)
    assert len(filtered) == 1


def test_clear_removes_state_file(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    mark_resolved("combo-a", sp)
    assert sp.exists()
    assert clear(sp) is True
    assert not sp.exists()
    # Second clear is a no-op
    assert clear(sp) is False


def test_state_path_for_returns_canonical_location(tmp_path):
    out_dir = tmp_path / "runtime-supervisor"
    sp = state_path_for(out_dir)
    assert sp == out_dir / "combos.state.yaml"


def test_malformed_yaml_load_returns_empty(tmp_path):
    sp = tmp_path / "combos.state.yaml"
    sp.write_text("not: valid: yaml: :\n  - a\n  - b")
    loaded = load(sp)
    # Degrades gracefully — caller sees no state, re-reports all combos.
    assert loaded == {}


def test_generator_respects_resolved_combos_end_to_end(tmp_path):
    """E2E: generar output, marcar un combo resolved, re-generar → ese
    combo ya no aparece en SUMMARY.md ni en la sección de combos del report.
    """
    from supervisor_discover.classifier import validate
    from supervisor_discover.findings import Finding
    from supervisor_discover.generator import generate

    # Findings que disparan el combo voice-clone + outbound-call
    findings = validate([
        Finding(
            scanner="voice-actions",
            file="/repo/src/tts.ts", line=10,
            snippet="elevenlabs.generate(", suggested_action_type="tool_use",
            confidence="high", rationale="voice synth",
            extra={"provider": "elevenlabs"},
        ),
        Finding(
            scanner="voice-actions",
            file="/repo/src/phone.ts", line=20,
            snippet="twilio.calls.create(", suggested_action_type="tool_use",
            confidence="high", rationale="outbound call",
            extra={"provider": "twilio"},
        ),
    ])
    out = tmp_path / "rs"
    generate(findings, out)

    # Primer scan: el combo aparece en la sección de combos del SUMMARY
    summary_v1 = (out / "SUMMARY.md").read_text()
    assert "## Combos detectados" in summary_v1
    assert "voice-clone-plus-outbound-call" in summary_v1

    # Usuario marca resolved
    mark_resolved("voice-clone-plus-outbound-call", state_path_for(out),
                  note="policy promoted + wraps applied")

    # Re-scan (re-generate con los mismos findings)
    generate(findings, out)
    summary_v2 = (out / "SUMMARY.md").read_text()

    # La sección dedicada "## Combos detectados" desaparece (ese era el único combo).
    # NOTE: el combo_id puede seguir apareciendo en los solution links de la
    # priority list (`→ ver combos/X.md`) — esos links son estáticos al playbook
    # en disco, no al combo detectado. Eso es correcto: el playbook sigue siendo
    # útil como referencia después de resuelto.
    assert "## Combos detectados" not in summary_v2

    # Con include_resolved=True la sección vuelve a aparecer
    generate(findings, out, include_resolved=True)
    summary_v3 = (out / "SUMMARY.md").read_text()
    assert "## Combos detectados" in summary_v3
    assert "voice-clone-plus-outbound-call" in summary_v3


def test_yaml_file_is_commit_friendly(tmp_path):
    """El archivo debe arrancar con un comentario explicativo y no cambiar
    de orden entre saves — necesario para diffs limpios en git."""
    sp = tmp_path / "combos.state.yaml"
    mark_resolved("zebra", sp, note="first")
    mark_resolved("alpha", sp, note="second")
    content = sp.read_text()
    assert content.startswith("# runtime-supervisor combo state")
    # Combos sorted alphabetically in the YAML output
    alpha_pos = content.find("alpha:")
    zebra_pos = content.find("zebra:")
    assert 0 < alpha_pos < zebra_pos
