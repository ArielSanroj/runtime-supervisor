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
    assert (out / "START_HERE.md").exists()
    assert (out / "FULL_REPORT.md").exists()
    assert (out / "ROLLOUT.md").exists()
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
    assert (tmp_path / "app/runtime-supervisor/START_HERE.md").exists()
    assert (tmp_path / "app/runtime-supervisor/FULL_REPORT.md").exists()
    # `init` drops a `.supervisor-ignore` template when missing.
    ignore = tmp_path / "app/.supervisor-ignore"
    assert ignore.exists()
    assert "PATH[:LINE]" in ignore.read_text()


def test_cli_init_writes_ci_workflow_when_flag_set(tmp_path, monkeypatch):
    """`init --ci` drops the GitHub Actions workflow with the scan +
    fail-on=new-high gate. Without `--ci` it stays absent so we don't
    surprise existing CI setups."""
    from supervisor_discover.cli import main

    import shutil
    shutil.copytree(FLASK_FIXTURE, tmp_path / "app")
    monkeypatch.chdir(tmp_path / "app")
    rc = main(["init", "--ci"])
    assert rc == 0
    workflow = tmp_path / "app/.github/workflows/runtime-supervisor.yml"
    assert workflow.exists()
    body = workflow.read_text()
    assert "supervisor-discover" in body
    assert "--fail-on=new-high" in body
    assert "--baseline runtime-supervisor/findings.json" in body


def test_cli_init_does_not_overwrite_existing_ignore(tmp_path, monkeypatch):
    """If the dev already has `.supervisor-ignore`, `init` must leave it
    alone — overwriting suppression history is a footgun."""
    from supervisor_discover.cli import main

    import shutil
    shutil.copytree(FLASK_FIXTURE, tmp_path / "app")
    custom = "src/x.py:42  reviewed-by-team  ariel\n"
    (tmp_path / "app/.supervisor-ignore").write_text(custom)
    monkeypatch.chdir(tmp_path / "app")
    main(["init"])
    assert (tmp_path / "app/.supervisor-ignore").read_text() == custom


def test_cli_init_does_not_overwrite_existing_ci_workflow(tmp_path, monkeypatch):
    """Same protection for the CI workflow."""
    from supervisor_discover.cli import main

    import shutil
    shutil.copytree(FLASK_FIXTURE, tmp_path / "app")
    ci_dir = tmp_path / "app/.github/workflows"
    ci_dir.mkdir(parents=True)
    custom_ci = "name: my-existing-workflow\non: pull_request\n"
    (ci_dir / "runtime-supervisor.yml").write_text(custom_ci)
    monkeypatch.chdir(tmp_path / "app")
    main(["init", "--ci"])
    assert (ci_dir / "runtime-supervisor.yml").read_text() == custom_ci


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
