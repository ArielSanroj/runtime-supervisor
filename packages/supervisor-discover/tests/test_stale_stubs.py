"""Tests for stale stub detection.

The reviewer flagged on supervincent that 19 stubs were marked `D` in
git status because the dev applied changes manually and the source
files moved. The reporter never told them which old stubs pointed at
moved code. Now each stub embeds a `stable_id` and on re-scan, stubs
whose id no longer matches a current finding get renamed to
`*.stale.stub.{py,ts}` so the dev sees them clearly.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.findings import Finding, assign_ids
from supervisor_discover.generator import _rename_stale_stubs


def _make_stub(path: Path, stable_id: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'"""\nGenerated stub.\nstable_id: {stable_id}\n"""\n')
    return path


def _f(scanner: str = "fs-shell", file: str = "/r/x.py", line: int = 1,
       snippet: str = "subprocess.run(") -> Finding:
    f = Finding(
        scanner=scanner, file=file, line=line, snippet=snippet,
        suggested_action_type="tool_use", confidence="high",
        rationale="...", extra={"family": "shell-exec"},
    )
    assign_ids([f])
    return f


def test_stub_with_matching_id_is_kept(tmp_path: Path):
    stubs_py = tmp_path / "stubs/py"
    f = _f()
    _make_stub(stubs_py / "x_L1.stub.py", f.id)
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [f])
    assert stale == 0
    assert (stubs_py / "x_L1.stub.py").exists()


def test_stub_with_obsolete_id_is_renamed(tmp_path: Path):
    stubs_py = tmp_path / "stubs/py"
    _make_stub(stubs_py / "x_L1.stub.py", "deadbeef0000")
    f = _f()  # different id from the stub
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [f])
    assert stale == 1
    assert not (stubs_py / "x_L1.stub.py").exists()
    assert (stubs_py / "x_L1.stale.stub.py").exists()


def test_legacy_stub_without_id_is_skipped(tmp_path: Path):
    """Older stubs (pre stable_id embed) just say `stable_id: (legacy)`
    or have nothing. Don't rename — the dev can clean up by hand."""
    stubs_py = tmp_path / "stubs/py"
    stubs_py.mkdir(parents=True)
    (stubs_py / "old.stub.py").write_text('"""no id embed"""\n')
    (stubs_py / "older.stub.py").write_text('"""\nstable_id: (legacy)\n"""\n')
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [])
    assert stale == 0
    assert (stubs_py / "old.stub.py").exists()
    assert (stubs_py / "older.stub.py").exists()


def test_already_renamed_stale_stub_is_idempotent(tmp_path: Path):
    """A `.stale.stub.py` from a prior scan must not be renamed again
    (we don't want `.stale.stale.stub.py`)."""
    stubs_py = tmp_path / "stubs/py"
    _make_stub(stubs_py / "x_L1.stale.stub.py", "deadbeef0001")
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [])
    assert stale == 0
    assert (stubs_py / "x_L1.stale.stub.py").exists()


def test_ts_stub_renamed_too(tmp_path: Path):
    stubs_ts = tmp_path / "stubs/ts"
    stubs_ts.mkdir(parents=True)
    (stubs_ts / "x_L1.stub.ts").write_text(
        '/**\n * stable_id: deadbeef0000\n */\n'
    )
    f = _f(file="/r/x.ts")
    stale = _rename_stale_stubs(tmp_path / "stubs/py", stubs_ts, [f])
    assert stale == 1
    assert (stubs_ts / "x_L1.stale.stub.ts").exists()


def test_stub_id_changed_renames(tmp_path: Path):
    """The supervincent shape: stub written for `payments.py:155` (Stripe).
    Dev reformats; `subprocess.run` swapped for `subprocess.Popen` — the
    finding's stable_id changes (different identifier), the stub points at
    a now-different call. Rename to .stale."""
    stubs_py = tmp_path / "stubs/py"
    f_old = _f(snippet="subprocess.run(")
    _make_stub(stubs_py / "x_L1.stub.py", f_old.id)
    # Same file/line, different identifier → different id.
    f_new = _f(snippet="subprocess.Popen(")
    assert f_old.id != f_new.id
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [f_new])
    assert stale == 1
    assert (stubs_py / "x_L1.stale.stub.py").exists()


def test_no_findings_renames_every_stub(tmp_path: Path):
    """Empty current findings = every stub is stale. Useful for "purge
    old stubs" workflows."""
    stubs_py = tmp_path / "stubs/py"
    _make_stub(stubs_py / "a_L1.stub.py", "abc123def456")
    _make_stub(stubs_py / "b_L2.stub.py", "abc123def457")
    stale = _rename_stale_stubs(stubs_py, tmp_path / "stubs/ts", [])
    assert stale == 2
