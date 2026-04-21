from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def test_cli_dry_run_prints_findings_json(tmp_path, capsys):
    from supervisor_discover.cli import main

    rc = main(["scan", "--path", str(FLASK_FIXTURE), "--out", str(tmp_path / "rs"), "--dry-run"])
    assert rc == 0
    captured = capsys.readouterr().out
    data = json.loads(captured)
    # New shape: { "repo_summary": {...}, "findings": [...] }
    assert set(data.keys()) == {"repo_summary", "findings"}
    assert isinstance(data["findings"], list)
    assert any(f["scanner"] == "payment-calls" for f in data["findings"])
    assert "frameworks" in data["repo_summary"]
    assert not (tmp_path / "rs").exists()  # dry-run didn't write


def test_cli_scan_writes_tree(tmp_path):
    from supervisor_discover.cli import main

    out = tmp_path / "rs"
    rc = main(["scan", "--path", str(FLASK_FIXTURE), "--out", str(out)])
    assert rc == 0
    assert (out / "report.md").exists()
    assert (out / "findings.json").exists()


def test_cli_init_alias(tmp_path, monkeypatch):
    from supervisor_discover.cli import main

    monkeypatch.chdir(tmp_path)
    # copy fixture over so cwd has something to scan
    import shutil
    shutil.copytree(FLASK_FIXTURE, tmp_path / "app")
    monkeypatch.chdir(tmp_path / "app")
    rc = main(["init"])
    assert rc == 0
    assert (tmp_path / "app/runtime-supervisor/report.md").exists()


def test_cli_path_not_found_returns_2():
    from supervisor_discover.cli import main
    rc = main(["scan", "--path", "/nonexistent/path/xyz", "--dry-run"])
    assert rc == 2


def test_cli_as_installed_script(tmp_path):
    """The `[project.scripts]` entry exposes `supervisor-discover`; verify it
    runs end-to-end through the package installation (this test will
    be skipped if the venv doesn't have it on PATH)."""
    rc = subprocess.run(
        [sys.executable, "-m", "supervisor_discover.cli", "scan", "--path", str(FLASK_FIXTURE), "--dry-run"],
        capture_output=True, text=True,
    )
    assert rc.returncode == 0
    assert "payment-calls" in rc.stdout
