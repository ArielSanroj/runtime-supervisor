"""`ac` — CLI for agentic-controls.

Commands:
    ac start        → launches supervisor + UI locally (one process tree)
    ac stop         → kills those processes
    ac status       → shows what's running + log paths
    ac scan [path]  → scans a repo and generates runtime-supervisor/
    ac review       → opens the review queue in the browser

Under the hood, `ac start` is the Python rewrite of the old quickstart.sh —
same outcome (supervisor on :8099, UI on :3099, SQLite audit log), but
fully in-process when possible and distributable via pipx.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path

SUPERVISOR_PORT = 8099
UI_PORT = 3099
STATE_DIR = Path("/tmp/agentic-controls-local")


# ── Helpers ───────────────────────────────────────────────────────────

def _c(color: str, text: str) -> str:
    codes = {"ok": "32", "warn": "33", "err": "31", "dim": "90"}
    if not sys.stderr.isatty():
        return text
    return f"\033[0;{codes[color]}m{text}\033[0m"


def _ok(msg: str) -> None:
    print(f"{_c('ok', '✓')} {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"{_c('warn', '!')} {msg}", file=sys.stderr)


def _die(msg: str, code: int = 1) -> None:
    print(f"{_c('err', '✗')} {msg}", file=sys.stderr)
    sys.exit(code)


def _http(method: str, url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("content-type", "application/json")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read()) if r.length != 0 else {}


def _http_status(method: str, url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, dict]:
    """Like _http, but returns (status, json) and does not raise on HTTPError."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if data is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            payload = json.loads(r.read()) if r.length != 0 else {}
            return r.status, payload
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}
        return e.code, payload


def _repo_root() -> Path:
    """Locate the monorepo root by walking up until we find pyproject.toml."""
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "pyproject.toml").exists() and (parent / "services" / "supervisor_api").exists():
            return parent
    _die("agentic-controls repo root not found — are you running from inside the monorepo?")
    raise SystemExit(1)  # pragma: no cover


# ── start ──────────────────────────────────────────────────────────────

def cmd_start(args: argparse.Namespace) -> int:
    STATE_DIR.mkdir(exist_ok=True)
    repo = _repo_root()

    # Fast path: if supervisor + UI are alive and creds are saved, reuse them.
    reused = _reuse_if_alive()
    if reused is not None:
        app_id, secret = reused
        _print_banner(app_id, secret)
        return 0

    _check_ports()
    db = STATE_DIR / "state.sqlite3"
    admin_token = f"ac-admin-{int(time.time())}"
    (STATE_DIR / "admin_token").write_text(admin_token)

    try:
        _migrate_db(repo, db)
        _start_supervisor(repo, db, admin_token)
        _wait_for_http(f"http://localhost:{SUPERVISOR_PORT}/v1/action-types", "supervisor", timeout=30)
        app_id, secret = _bootstrap(admin_token)
        _seed_policies(repo, admin_token)
        _start_ui(repo, app_id, secret)
        _wait_for_http(f"http://localhost:{UI_PORT}/login", "UI", timeout=45)
    except BaseException:
        _teardown_on_failure()
        raise
    _print_banner(app_id, secret)
    return 0


def _reuse_if_alive() -> tuple[str, str] | None:
    """Return (app_id, secret) if supervisor + UI pid files point to live processes
    and the credential files are present. Otherwise return None."""
    for svc in ("supervisor", "ui"):
        pid_file = STATE_DIR / f"{svc}.pid"
        if not pid_file.exists():
            return None
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
        except (ProcessLookupError, ValueError):
            return None
    app_id_file = STATE_DIR / "ui_app_id"
    secret_file = STATE_DIR / "ui_secret"
    if not (app_id_file.exists() and secret_file.exists()):
        return None
    _ok("supervisor y UI ya corrían — reutilizando")
    return app_id_file.read_text().strip(), secret_file.read_text().strip()


def _teardown_on_failure() -> None:
    """Kill any partially-started services so the next `ac start` can run cleanly."""
    _warn("falló el arranque — limpiando procesos parciales…")
    for svc in ("supervisor", "ui"):
        pid_file = STATE_DIR / f"{svc}.pid"
        if not pid_file.exists():
            continue
        try:
            pid = int(pid_file.read_text().strip())
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass
        pid_file.unlink(missing_ok=True)


def _check_ports() -> None:
    # First: if a previous `ac start` left a tracked pid file and the process is alive,
    # fail with a clear message. Stale pid files are cleaned up.
    for svc in ("supervisor", "ui"):
        pid_file = STATE_DIR / f"{svc}.pid"
        if not pid_file.exists():
            continue
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            _die(f"{svc} ya corre (pid {pid}). Corré `ac stop` primero.")
        except (ProcessLookupError, ValueError):
            pid_file.unlink(missing_ok=True)

    # Second: if something else (untracked) is listening on our ports, bail out.
    # HTTPError is a URLError subclass — a response (any status) means something is bound.
    for port in (SUPERVISOR_PORT, UI_PORT):
        try:
            urllib.request.urlopen(f"http://localhost:{port}", timeout=1)
        except urllib.error.HTTPError:
            _die(f"puerto {port} ocupado por otro proceso. Matá: lsof -ti:{port} | xargs kill -9")
        except urllib.error.URLError:
            continue  # nothing listening → free
        except Exception:
            continue
        _die(f"puerto {port} ocupado por otro proceso. Matá: lsof -ti:{port} | xargs kill -9")


def _migrate_db(repo: Path, db: Path) -> None:
    print(_c("dim", "→ aplicando migraciones…"), file=sys.stderr)
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db}"}
    subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=repo / "services" / "supervisor_api", env=env, check=True, capture_output=True,
    )


def _start_supervisor(repo: Path, db: Path, admin_token: str) -> None:
    print(_c("dim", f"→ arrancando supervisor en :{SUPERVISOR_PORT}…"), file=sys.stderr)
    env = {
        **os.environ,
        "ADMIN_BOOTSTRAP_TOKEN": admin_token,
        "EVIDENCE_HMAC_SECRET": "ac-hmac-local",
        "WEBHOOK_SECRET": "ac-webhook-local",
        "DATABASE_URL": f"sqlite:///{db}",
        "POLICY_PATH": str(repo / "packages" / "policies" / "refund.base.v1.yaml"),
        "REQUIRE_AUTH": "true",
        "SUPERVISOR_SKIP_SEED": "true",
    }
    log_path = STATE_DIR / "supervisor.log"
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            ["uv", "run", "uvicorn", "supervisor_api.main:app",
             "--port", str(SUPERVISOR_PORT),
             "--app-dir", "services/supervisor_api/src"],
            cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    (STATE_DIR / "supervisor.pid").write_text(str(proc.pid))


def _bootstrap(admin_token: str) -> tuple[str, str]:
    print(_c("dim", "→ creando user admin + integration…"), file=sys.stderr)
    base = f"http://localhost:{SUPERVISOR_PORT}"
    admin_hdrs = {"X-Admin-Token": admin_token}

    # Admin user — 409 means it already exists from a prior run; password is deterministic.
    status, _ = _http_status("POST", f"{base}/v1/users", headers=admin_hdrs,
                             body={"email": "test@local", "password": "test-pass-1234", "role": "admin"})
    if status not in (200, 201, 409):
        _die(f"user bootstrap failed (HTTP {status})")

    # UI integration — on 409, find existing by name and rotate the secret to recover it.
    status, body = _http_status("POST", f"{base}/v1/integrations", headers=admin_hdrs,
                                body={"name": "ui-local", "scopes": ["*"]})
    if status in (200, 201):
        app_id, secret = body["id"], body["shared_secret"]
    elif status == 409:
        existing = _http("GET", f"{base}/v1/integrations", headers=admin_hdrs)
        match = next((i for i in existing if i.get("name") == "ui-local"), None)
        if not match:
            _die("integration 'ui-local' already exists but could not be listed")
        rotated = _http("POST", f"{base}/v1/integrations/{match['id']}/rotate-secret", headers=admin_hdrs)
        app_id, secret = rotated["id"], rotated["shared_secret"]
    else:
        _die(f"integration bootstrap failed (HTTP {status})")

    (STATE_DIR / "ui_app_id").write_text(app_id)
    (STATE_DIR / "ui_secret").write_text(secret)
    return app_id, secret


def _seed_policies(repo: Path, admin_token: str) -> None:
    for pol in ("refund", "payment", "tool_use", "account_change", "data_access", "compliance"):
        yaml_src = repo / "packages" / "policies" / f"{pol}.base.v1.yaml"
        if not yaml_src.exists():
            continue
        try:
            _http("POST", f"http://localhost:{SUPERVISOR_PORT}/v1/policies",
                  headers={"X-Admin-Token": admin_token},
                  body={"action_type": pol, "yaml_source": yaml_src.read_text(), "promote": True})
        except Exception:
            pass  # best-effort


def _start_ui(repo: Path, app_id: str, secret: str) -> None:
    print(_c("dim", f"→ arrancando control-center en :{UI_PORT}…"), file=sys.stderr)
    env = {
        **os.environ,
        "SUPERVISOR_API_URL": f"http://localhost:{SUPERVISOR_PORT}",
        "SUPERVISOR_APP_ID": app_id,
        "SUPERVISOR_SECRET": secret,
        "SESSION_SECRET": "ac-webhook-local",
    }
    log_path = STATE_DIR / "ui.log"
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            ["pnpm", "exec", "next", "dev", "-p", str(UI_PORT)],
            cwd=repo / "apps" / "control-center", env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    (STATE_DIR / "ui.pid").write_text(str(proc.pid))


def _wait_for_http(url: str, name: str, *, timeout: int) -> None:
    for _ in range(timeout):
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status in (200, 307):
                    _ok(f"{name} up en {url.rsplit('/', 1)[0]}")
                    return
        except Exception:
            time.sleep(1)
    log_hint = STATE_DIR / f"{name.lower()}.log"
    _die(f"{name} no arrancó en {timeout}s. Ver {log_hint}")


def _print_banner(app_id: str, secret: str) -> None:
    bar = _c("ok", "═" * 58)
    print("", file=sys.stderr)
    print(bar, file=sys.stderr)
    print(_c("ok", "  Todo listo. Entrá al panel:"), file=sys.stderr)
    print(bar, file=sys.stderr)
    print("", file=sys.stderr)
    print(f"  🌐 URL:      {_c('ok', f'http://localhost:{UI_PORT}')}", file=sys.stderr)
    print(f"  📧 Email:    test@local", file=sys.stderr)
    print(f"  🔑 Password: test-pass-1234", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Para conectar tu agente:", file=sys.stderr)
    print(f"    {_c('dim', f'SUPERVISOR_BASE_URL=http://localhost:{SUPERVISOR_PORT}')}", file=sys.stderr)
    print(f"    {_c('dim', f'SUPERVISOR_APP_ID={app_id}')}", file=sys.stderr)
    print(f"    {_c('dim', f'SUPERVISOR_SECRET={secret}')}", file=sys.stderr)
    print(f"    {_c('dim', 'SUPERVISOR_ENFORCEMENT_MODE=shadow')}", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"  Parar:  {_c('dim', 'ac stop')}", file=sys.stderr)
    print(f"  Estado: {_c('dim', 'ac status')}", file=sys.stderr)
    print(f"  Logs:   {_c('dim', f'tail -f {STATE_DIR}/*.log')}", file=sys.stderr)
    print("", file=sys.stderr)


# ── stop / status ────────────────────────────────────────────────────

def cmd_stop(args: argparse.Namespace) -> int:
    for svc in ("supervisor", "ui"):
        pid_file = STATE_DIR / f"{svc}.pid"
        if not pid_file.exists():
            continue
        try:
            pid = int(pid_file.read_text().strip())
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            _ok(f"{svc} detenido (pid {pid})")
        except ProcessLookupError:
            _warn(f"{svc} no estaba corriendo")
        except Exception as exc:
            _warn(f"no pude matar {svc}: {exc}")
        pid_file.unlink(missing_ok=True)
    _ok("state limpio")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    any_running = False
    for svc in ("supervisor", "ui"):
        pid_file = STATE_DIR / f"{svc}.pid"
        if not pid_file.exists():
            _warn(f"{svc} no corre")
            continue
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            _ok(f"{svc} corriendo (pid {pid}) — logs: {STATE_DIR}/{svc}.log")
            any_running = True
        except (ProcessLookupError, ValueError):
            _warn(f"{svc} stale (pid archivo pero proceso muerto)")
            pid_file.unlink(missing_ok=True)
    if not any_running:
        print(_c("dim", "  Nada corriendo. Arrancá con: ac start"), file=sys.stderr)
    return 0


# ── scan / review ────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    from supervisor_discover.cli import main as discover_main
    sub_args = ["scan"]
    if args.path:
        sub_args += ["--path", args.path]
    if args.out:
        sub_args += ["--out", args.out]
    if args.dry_run:
        sub_args.append("--dry-run")
    return discover_main(sub_args)


def cmd_review(args: argparse.Namespace) -> int:
    if not (STATE_DIR / "ui.pid").exists():
        _die("UI no está corriendo. Arrancá con `ac start` primero.")
    url = f"http://localhost:{UI_PORT}/review?status=pending"
    _ok(f"abriendo {url}")
    webbrowser.open(url)
    return 0


# ── main ─────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ac", description="Agentic Controls — radar for AI-agent actions.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("start", help="Launch supervisor + UI locally").set_defaults(func=cmd_start)
    sub.add_parser("stop", help="Stop local services").set_defaults(func=cmd_stop)
    sub.add_parser("status", help="Show what's running").set_defaults(func=cmd_status)

    scan_p = sub.add_parser("scan", help="Scan a repo and generate runtime-supervisor/")
    scan_p.add_argument("path", nargs="?", default=None)
    scan_p.add_argument("--out", default=None)
    scan_p.add_argument("--dry-run", action="store_true")
    scan_p.set_defaults(func=cmd_scan)

    sub.add_parser("review", help="Open the pending review queue in the browser").set_defaults(func=cmd_review)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
