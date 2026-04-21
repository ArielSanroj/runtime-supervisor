#!/usr/bin/env bash
# quickstart — levanta el supervisor + UI local para pruebas.
#
# Uso:
#   ./quickstart.sh            → arranca todo
#   ./quickstart.sh stop       → mata procesos + limpia
#   ./quickstart.sh status     → ver qué está corriendo
#
# No toca nada fuera de /tmp/supervisor-local/. Todo local, SQLite,
# sin TLS, sin Docker. Perfecto para probar o hacer demos.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="/tmp/supervisor-local"
DB="${STATE_DIR}/supervisor.sqlite3"
SUPERVISOR_PORT=8000
UI_PORT=3001
ADMIN_TOKEN="local-admin-$(date +%s)"
USER_EMAIL="test@local"
USER_PASSWORD="test-pass-1234"

# ── Colors ────────────────────────────────────────────────────────────
c_ok=$'\033[0;32m'; c_warn=$'\033[0;33m'; c_err=$'\033[0;31m'; c_dim=$'\033[0;90m'; c_reset=$'\033[0m'
say() { printf '%b\n' "$1"; }
ok()  { say "${c_ok}✓${c_reset} $1"; }
warn(){ say "${c_warn}!${c_reset} $1"; }
die() { say "${c_err}✗${c_reset} $1"; exit 1; }

# ── Subcommands ───────────────────────────────────────────────────────

cmd_stop() {
  [ -f "${STATE_DIR}/supervisor.pid" ] && kill "$(cat "${STATE_DIR}/supervisor.pid")" 2>/dev/null && ok "supervisor detenido" || true
  [ -f "${STATE_DIR}/ui.pid" ]         && kill "$(cat "${STATE_DIR}/ui.pid")"         2>/dev/null && ok "UI detenida"         || true
  rm -rf "${STATE_DIR}"
  ok "state limpio"
}

cmd_status() {
  for svc in supervisor ui; do
    if [ -f "${STATE_DIR}/${svc}.pid" ] && kill -0 "$(cat "${STATE_DIR}/${svc}.pid")" 2>/dev/null; then
      ok "${svc} corriendo (pid $(cat "${STATE_DIR}/${svc}.pid")) → logs: ${STATE_DIR}/${svc}.log"
    else
      warn "${svc} no corre"
    fi
  done
}

# ── Prereqs ───────────────────────────────────────────────────────────

check_prereqs() {
  command -v uv  >/dev/null || die "falta 'uv'. Instalar: brew install uv  (o curl -LsSf https://astral.sh/uv/install.sh | sh)"
  command -v pnpm >/dev/null || die "falta 'pnpm'. Instalar: brew install pnpm  (o corepack enable)"
  command -v curl >/dev/null || die "falta 'curl'"
  command -v python3 >/dev/null || die "falta python3"
}

check_ports() {
  for port in "$SUPERVISOR_PORT" "$UI_PORT"; do
    if lsof -i ":${port}" >/dev/null 2>&1; then
      die "puerto ${port} ya está en uso. Cerralo con: lsof -ti:${port} | xargs kill"
    fi
  done
}

# ── Supervisor + UI ───────────────────────────────────────────────────

start_supervisor() {
  mkdir -p "$STATE_DIR"
  say "${c_dim}→ aplicando migraciones…${c_reset}"
  (
    cd "${REPO}/services/supervisor_api"
    DATABASE_URL="sqlite:///${DB}" uv run alembic upgrade head >/dev/null 2>&1
  )

  say "${c_dim}→ arrancando supervisor en :${SUPERVISOR_PORT}…${c_reset}"
  (
    cd "$REPO"
    ADMIN_BOOTSTRAP_TOKEN="$ADMIN_TOKEN" \
    EVIDENCE_HMAC_SECRET="local-hmac" \
    WEBHOOK_SECRET="local-webhook" \
    DATABASE_URL="sqlite:///${DB}" \
    POLICY_PATH="${REPO}/packages/policies/refund.base.v1.yaml" \
    REQUIRE_AUTH=true \
    SUPERVISOR_SKIP_SEED=true \
    uv run uvicorn supervisor_api.main:app --port "$SUPERVISOR_PORT" --app-dir services/supervisor_api/src \
      >"${STATE_DIR}/supervisor.log" 2>&1 &
    echo $! > "${STATE_DIR}/supervisor.pid"
  )

  for _ in {1..30}; do
    if curl -fs "http://localhost:${SUPERVISOR_PORT}/v1/action-types" >/dev/null 2>&1; then
      ok "supervisor up en http://localhost:${SUPERVISOR_PORT}"
      return
    fi
    sleep 1
  done
  die "supervisor no arrancó en 30s. Ver ${STATE_DIR}/supervisor.log"
}

bootstrap_data() {
  say "${c_dim}→ creando user admin + integration…${c_reset}"

  # Admin user para loggearse al UI.
  curl -sf -X POST "http://localhost:${SUPERVISOR_PORT}/v1/users" \
    -H "X-Admin-Token: ${ADMIN_TOKEN}" \
    -H "content-type: application/json" \
    -d "{\"email\":\"${USER_EMAIL}\",\"password\":\"${USER_PASSWORD}\",\"role\":\"admin\"}" \
    >/dev/null

  # Integration para el UI (server → server JWT).
  INTEG=$(curl -sf -X POST "http://localhost:${SUPERVISOR_PORT}/v1/integrations" \
    -H "X-Admin-Token: ${ADMIN_TOKEN}" \
    -H "content-type: application/json" \
    -d '{"name":"ui-local","scopes":["*"]}')
  echo "$INTEG" > "${STATE_DIR}/ui_integration.json"

  UI_APP_ID=$(echo "$INTEG" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  UI_SECRET=$(echo "$INTEG" | python3 -c 'import json; import sys; print(json.load(sys.stdin)["shared_secret"])')

  # Policies: promover las 6 shipped para que la UI pueda editarlas.
  for pol in refund payment tool_use account_change data_access compliance; do
    yaml_src="${REPO}/packages/policies/${pol}.base.v1.yaml"
    [ -f "$yaml_src" ] || continue
    POLICY=$(python3 -c 'import json,sys; print(json.dumps(open(sys.argv[1]).read()))' "$yaml_src")
    curl -sf -X POST "http://localhost:${SUPERVISOR_PORT}/v1/policies" \
      -H "X-Admin-Token: ${ADMIN_TOKEN}" \
      -H "content-type: application/json" \
      -d "{\"action_type\":\"${pol}\",\"yaml_source\":${POLICY},\"promote\":true}" \
      >/dev/null 2>&1 || true
  done

  # Exportar para el siguiente start del UI.
  echo "$UI_APP_ID" > "${STATE_DIR}/ui_app_id"
  echo "$UI_SECRET" > "${STATE_DIR}/ui_secret"
  ok "data sembrada"
}

start_ui() {
  say "${c_dim}→ arrancando control-center en :${UI_PORT}…${c_reset}"
  UI_APP_ID=$(cat "${STATE_DIR}/ui_app_id")
  UI_SECRET=$(cat "${STATE_DIR}/ui_secret")

  (
    cd "${REPO}/apps/control-center"
    SUPERVISOR_API_URL="http://localhost:${SUPERVISOR_PORT}" \
    SUPERVISOR_APP_ID="$UI_APP_ID" \
    SUPERVISOR_SECRET="$UI_SECRET" \
    SESSION_SECRET="local-webhook" \
    pnpm exec next dev -p "$UI_PORT" \
      >"${STATE_DIR}/ui.log" 2>&1 &
    echo $! > "${STATE_DIR}/ui.pid"
  )

  for _ in {1..45}; do
    if curl -fs "http://localhost:${UI_PORT}/login" >/dev/null 2>&1; then
      ok "UI up en http://localhost:${UI_PORT}"
      return
    fi
    sleep 1
  done
  die "UI no arrancó en 45s. Ver ${STATE_DIR}/ui.log"
}

# ── Main ──────────────────────────────────────────────────────────────

case "${1:-start}" in
  stop)   cmd_stop; exit 0 ;;
  status) cmd_status; exit 0 ;;
  start)  ;;
  *)      die "uso: ./quickstart.sh [start|stop|status]" ;;
esac

check_prereqs
check_ports

start_supervisor
bootstrap_data
start_ui

say ""
say "${c_ok}══════════════════════════════════════════════════════════${c_reset}"
say "${c_ok}  Todo listo. Entrá al panel:${c_reset}"
say "${c_ok}══════════════════════════════════════════════════════════${c_reset}"
say ""
say "  🌐 URL:      ${c_ok}http://localhost:${UI_PORT}${c_reset}"
say "  📧 Email:    ${USER_EMAIL}"
say "  🔑 Password: ${USER_PASSWORD}"
say ""
say "  Logs:       ${c_dim}tail -f ${STATE_DIR}/*.log${c_reset}"
say "  Parar:      ${c_dim}./quickstart.sh stop${c_reset}"
say ""
say "  Para conectar un agente a este supervisor, copiá esto al .env del cliente:"
say "    ${c_dim}SUPERVISOR_BASE_URL=http://localhost:${SUPERVISOR_PORT}${c_reset}"
say "    ${c_dim}SUPERVISOR_APP_ID=$(cat "${STATE_DIR}/ui_app_id")${c_reset}"
say "    ${c_dim}SUPERVISOR_SECRET=$(cat "${STATE_DIR}/ui_secret")${c_reset}"
say "    ${c_dim}SUPERVISOR_ENFORCEMENT_MODE=shadow${c_reset}"
say ""
