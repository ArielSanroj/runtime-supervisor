"""Unit tests for `agentic_controls.cli` — bootstrap + port checks.

These tests exercise the CLI's HTTP choreography without starting a real
supervisor. They cover the regression paths that broke `ac start`:

  1. First-time bootstrap (201 on user + integration)
  2. Second-run bootstrap (user 409 swallowed, integration 409 → rotate-secret)
  3. Port collision with a foreign HTTP process (HTTPError is a URLError
     subclass, so the naïve `except URLError` was silently swallowing it).
"""
from __future__ import annotations

import urllib.error

import pytest

from agentic_controls import cli


@pytest.fixture(autouse=True)
def redirect_state(tmp_path, monkeypatch):
    """Point STATE_DIR at a tmp dir so tests don't touch /tmp/agentic-controls-local."""
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    return tmp_path


# ── _bootstrap ────────────────────────────────────────────────────────

def test_bootstrap_fresh_create(monkeypatch, redirect_state):
    """First run: both POSTs return 201; no rotate needed."""
    def fake_http_status(method, url, headers=None, body=None):
        if url.endswith("/v1/users"):
            return 201, {}
        if url.endswith("/v1/integrations"):
            return 201, {"id": "app-1", "shared_secret": "sec-1"}
        raise AssertionError(f"unexpected {method} {url}")

    def fake_http(method, url, headers=None, body=None):
        raise AssertionError(f"_http should not be called; got {method} {url}")

    monkeypatch.setattr(cli, "_http_status", fake_http_status)
    monkeypatch.setattr(cli, "_http", fake_http)

    app_id, secret = cli._bootstrap("tok")

    assert (app_id, secret) == ("app-1", "sec-1")
    assert (redirect_state / "ui_app_id").read_text() == "app-1"
    assert (redirect_state / "ui_secret").read_text() == "sec-1"


def test_bootstrap_user_conflict_is_swallowed(monkeypatch, redirect_state):
    """Re-run with DB still containing test@local: 409 must not abort."""
    def fake_http_status(method, url, headers=None, body=None):
        if url.endswith("/v1/users"):
            return 409, {"detail": "user conflict"}
        if url.endswith("/v1/integrations"):
            return 201, {"id": "app-2", "shared_secret": "sec-2"}
        raise AssertionError(f"unexpected {method} {url}")

    monkeypatch.setattr(cli, "_http_status", fake_http_status)

    app_id, secret = cli._bootstrap("tok")
    assert (app_id, secret) == ("app-2", "sec-2")


def test_bootstrap_integration_conflict_rotates(monkeypatch, redirect_state):
    """Re-run when ui-local integration exists: list → rotate-secret."""
    def fake_http_status(method, url, headers=None, body=None):
        if url.endswith("/v1/users"):
            return 201, {}
        if method == "POST" and url.endswith("/v1/integrations"):
            return 409, {"detail": "integration name conflict"}
        raise AssertionError(f"unexpected _http_status {method} {url}")

    def fake_http(method, url, headers=None, body=None):
        if method == "GET" and url.endswith("/v1/integrations"):
            return [
                {"id": "existing-app", "name": "ui-local"},
                {"id": "other", "name": "other"},
            ]
        if method == "POST" and url.endswith("/v1/integrations/existing-app/rotate-secret"):
            return {"id": "existing-app", "shared_secret": "rotated-secret"}
        raise AssertionError(f"unexpected _http {method} {url}")

    monkeypatch.setattr(cli, "_http_status", fake_http_status)
    monkeypatch.setattr(cli, "_http", fake_http)

    app_id, secret = cli._bootstrap("tok")
    assert (app_id, secret) == ("existing-app", "rotated-secret")
    assert (redirect_state / "ui_secret").read_text() == "rotated-secret"


def test_bootstrap_user_unexpected_status_dies(monkeypatch, redirect_state):
    """Any non-2xx/409 on user create aborts; prevents silent 401 scenarios."""
    monkeypatch.setattr(cli, "_http_status", lambda *a, **kw: (500, {}))
    with pytest.raises(SystemExit):
        cli._bootstrap("tok")


# ── _check_ports ──────────────────────────────────────────────────────

def test_check_ports_detects_httperror(monkeypatch, redirect_state):
    """HTTPError is a URLError subclass; _check_ports must still bail out."""
    def fake_urlopen(url, timeout=1):
        target = url if isinstance(url, str) else url.full_url
        if f"localhost:{cli.SUPERVISOR_PORT}" in target:
            raise urllib.error.HTTPError(target, 404, "Not Found", {}, None)
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(SystemExit):
        cli._check_ports()


def test_check_ports_free_when_nothing_listens(monkeypatch, redirect_state):
    """No pid files and no one listening → pass through without raising."""
    def fake_urlopen(url, timeout=1):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    cli._check_ports()  # must not raise


def test_check_ports_dies_when_tracked_pid_alive(monkeypatch, redirect_state):
    """Live tracked pid → instruct user to run `ac stop`."""
    (redirect_state / "supervisor.pid").write_text("1")  # PID 1 (init) always exists
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: None)

    with pytest.raises(SystemExit):
        cli._check_ports()


# ── _reuse_if_alive ───────────────────────────────────────────────────

def test_reuse_returns_saved_creds_when_pids_alive(monkeypatch, redirect_state):
    (redirect_state / "supervisor.pid").write_text("1")
    (redirect_state / "ui.pid").write_text("1")
    (redirect_state / "ui_app_id").write_text("saved-app")
    (redirect_state / "ui_secret").write_text("saved-secret")
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: None)

    assert cli._reuse_if_alive() == ("saved-app", "saved-secret")


def test_reuse_returns_none_when_creds_missing(monkeypatch, redirect_state):
    (redirect_state / "supervisor.pid").write_text("1")
    (redirect_state / "ui.pid").write_text("1")
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: None)

    assert cli._reuse_if_alive() is None


def test_reuse_returns_none_when_pid_dead(monkeypatch, redirect_state):
    (redirect_state / "supervisor.pid").write_text("999999")
    (redirect_state / "ui.pid").write_text("999999")
    (redirect_state / "ui_app_id").write_text("saved-app")
    (redirect_state / "ui_secret").write_text("saved-secret")

    def dead(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(cli.os, "kill", dead)
    assert cli._reuse_if_alive() is None


# ── _teardown_on_failure ──────────────────────────────────────────────

def test_teardown_kills_and_removes_pid_files(monkeypatch, redirect_state):
    (redirect_state / "supervisor.pid").write_text("42")
    (redirect_state / "ui.pid").write_text("43")
    killed = []
    monkeypatch.setattr(cli.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(cli.os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))

    cli._teardown_on_failure()

    assert sorted(pgid for pgid, _ in killed) == [42, 43]
    assert not (redirect_state / "supervisor.pid").exists()
    assert not (redirect_state / "ui.pid").exists()


def test_teardown_tolerates_dead_pid(monkeypatch, redirect_state):
    """If the spawned process already died, teardown must not crash."""
    (redirect_state / "supervisor.pid").write_text("42")

    def explode(*a, **kw):
        raise ProcessLookupError

    monkeypatch.setattr(cli.os, "getpgid", explode)
    cli._teardown_on_failure()  # must not raise
    assert not (redirect_state / "supervisor.pid").exists()
