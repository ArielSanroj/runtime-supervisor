"""Literal templates for generated files.

The report is organized by RISK TIER, not by action_type. Each tier opens
with an "Observa / Evalúa / Intervendría" block so a CFO/CRO/CISO reading
this doesn't need to know what `action_type=refund` means — they read what
the supervisor would actually do.
"""
from __future__ import annotations

REPORT_HEADER = """# Runtime supervisor — discovery report

Auto-generado por `supervisor-discover scan`. Commit este archivo (y el
resto de `runtime-supervisor/`) para que cada PR se pueda revisar contra
lo que el supervisor debe gatear.

El supervisor hace tres cosas con estos hallazgos:

- **Observa** cada llamada que pasa por los call-sites listados abajo.
- **Evalúa** el payload contra la política del `action_type` + el pipeline
  de amenazas (prompt-injection, jailbreak, PII exfil — OWASP LLM Top 10).
- **Interviene** cuando la política falla o el riesgo supera el umbral:
  bloquea (deny), escala a humano (review), o deja pasar (allow).

## Resumen

| Tier | High | Medium | Low | Total |
|---|---:|---:|---:|---:|
{tier_summary_table}

**Total de hallazgos:** {total}

{headline_note}

## Cómo desplegar esto sin romper producción

Los stubs generados vienen con `on_review="shadow"` por default — al
pegarlos en tu código, el supervisor evalúa cada llamada y registra lo
que habría hecho, pero **no bloquea**. Mira `runtime-supervisor/ROLLOUT.md`
para el playbook adaptado a la superficie detectada en este repo
(shadow → sample → enforce por tier, con criterios de volumen y FP rate
por fase).

Medición post-deploy: `GET ${{SUPERVISOR_BASE_URL}}/v1/metrics/enforcement`
devuelve cuántas llamadas habría bloqueado shadow, cuántas bloqueó
enforce, tasa estimada de falso-positivo, y latencia p50/p95/p99.

---

"""

# Per-tier copy block. Substituted into _render_by_risk_tier in the generator.
TIER_COPY = {
    "money": {
        "title": "Money movement",
        "observa": (
            "{total} punto(s) en tu código que pueden iniciar un refund, charge, "
            "subscription o payout sin pasar por el supervisor."
        ),
        "evalua": (
            "El supervisor evaluaría cada llamada contra la política `payment.base.v1` "
            "(hard-cap amount, velocity, customer-age) + detectores de prompt-injection "
            "si el monto proviene de un LLM."
        ),
        "intervendria": (
            "Bloquearía la llamada si el payload falla la política. La mandaría a review "
            "humano si el risk score es ≥50. En shadow mode, solo registra la decisión "
            "sin interrumpir el flujo."
        ),
    },
    "real_world_actions": {
        "title": "Real-world actions",
        "observa": (
            "{total} call-site(s) donde el agente actúa en el mundo real: llamadas "
            "telefónicas, SMS, emails, posts en Slack/Discord, eventos de calendario, "
            "escrituras a disco, exec shell, o generación de media sintética."
        ),
        "evalua": (
            "El supervisor evaluaría cada llamada contra `tool_use.base.v1` (tool name "
            "requerido, prompt length, namespace privilegiado) + detectores OWASP "
            "(prompt-injection que manipule destinatarios, comandos, o contenido)."
        ),
        "intervendria": (
            "Bloquearía llamadas a tools prohibidas (shell, fs.delete, network.raw). "
            "Escalaría a humano cualquier acción que envíe mensaje, llame, o agende con "
            "contenido sospechoso. En shadow mode, solo registra — útil para construir "
            "allowlist de destinatarios/tools reales antes de enforzar."
        ),
    },
    "customer_data": {
        "title": "Customer data",
        "observa": (
            "{total} mutación(es) sobre tablas con nombres tipo users / accounts / "
            "customers / orders — datos sensibles desde perspectiva de cumplimiento."
        ),
        "evalua": (
            "El supervisor evaluaría el DELETE/UPDATE/INSERT contra políticas de "
            "`account_change` / `data_access` (quién, qué campos, scope), más detección "
            "de PII exfil en el resultado."
        ),
        "intervendria": (
            "Bloquearía mutaciones fuera del scope autorizado. Emitiría evidence-log "
            "con hash-chain para cumplimiento (GDPR/SOC2). En review, notificaría al "
            "DPO antes de permitir."
        ),
    },
    "llm": {
        "title": "LLM tool-use",
        "observa": (
            "{total} invocación(es) de LLM SDKs (openai / anthropic / langchain / "
            "llama_index) — superficie primaria para prompt-injection y jailbreak."
        ),
        "evalua": (
            "El supervisor evaluaría el prompt + tool-call contra su pipeline de amenazas "
            "OWASP LLM Top 10 (prompt-injection, sensitive-info-disclosure, "
            "excessive-agency, unbounded-consumption)."
        ),
        "intervendria": (
            "Bloquearía llamadas con prompts inyectados o que pidan acciones fuera del "
            "scope del agente. Escalaría a review si detecta PII en el input. En shadow, "
            "marca la llamada sin interrumpir."
        ),
    },
    "general": {
        "title": "General / informational",
        "observa": (
            "{total} hallazgo(s) informativo(s) (HTTP routes, cron schedules, otros). "
            "No mueven dinero ni tocan datos críticos directamente — pero son el "
            "mapa de la superficie de ataque del repo."
        ),
        "evalua": (
            "No requieren stub en esta fase. Útiles para auditoría y para catalogar "
            "qué partes del repo tienen lógica que el supervisor aún no gatea."
        ),
        "intervendria": (
            "N/A en esta fase. Próximas iteraciones podrán gatear cron jobs con "
            "ejecución idempotente y rate-limits por route."
        ),
    },
}

PY_STUB = '''"""Generated by supervisor-discover. Copy the supervised() wrapper into
{original_file}:{line} and adapt the payload extractor to match the real
arguments of the function being guarded.

Original call-site: {snippet}
Suggested action_type: {action_type}
Rationale: {rationale}
"""
from supervisor_guards import SupervisorBlocked, supervised


# NOTE: `on_review="shadow"` means the supervisor evaluates every call but
# NEVER blocks — safe to deploy on day 1. When you're ready to actually
# gate calls, switch to on_review="block" (polls for human review) or
# on_review="fail_closed" (async flows). See runtime-supervisor/ROLLOUT.md.
@supervised(
    "{action_type}",
    on_review="shadow",
    payload=lambda *args, **kwargs: {{
        # TODO: build the payload the supervisor should see. At minimum
        # include the fields your policy's `when` expressions reference —
        # for refund: amount, currency, customer_id, customer_age_days,
        # refund_velocity_24h, reason.
        "raw_args": [str(a) for a in args],
        "raw_kwargs": {{k: str(v) for k, v in kwargs.items()}},
    }},
)
def guarded_call(*args, **kwargs):
    # Replace with the original call found at {original_file}:{line}
    # e.g. return stripe.Refund.create(**kwargs)
    raise NotImplementedError
'''

TS_STUB = """/**
 * Generated by supervisor-discover. Copy the `supervised()` wrapper into
 * {original_file}:{line}.
 *
 * Original call-site: {snippet}
 * Suggested action_type: {action_type}
 * Rationale: {rationale}
 *
 * NOTE: `onReview: "shadow"` means the supervisor evaluates every call but
 * NEVER blocks — safe to deploy on day 1. When you're ready to actually
 * gate calls, switch to onReview: "block" (polls for human review) or
 * onReview: "fail_closed" (async flows). See runtime-supervisor/ROLLOUT.md.
 */
import {{ SupervisorBlocked, supervised }} from "@runtime-supervisor/guards";

export const guardedCall = supervised("{action_type}", {{
  onReview: "shadow",
  payloadFrom: (...args: unknown[]) => ({{
    // TODO: build the payload the supervisor should see.
    raw_args: args.map((a) => String(a)),
  }}),
}})(async (...args: unknown[]) => {{
  // TODO: call the original function found at {original_file}:{line}
  throw new Error("wire me into the real call-site");
}});
"""

ENV_EXAMPLE = """# runtime-supervisor client env
SUPERVISOR_BASE_URL=http://localhost:8000
SUPERVISOR_APP_ID=
SUPERVISOR_SECRET=
SUPERVISOR_SCOPES=*
# Enforcement mode controls whether guards actually block.
#   shadow  = evaluate + log, never block (safe default for first deploy)
#   sample  = enforce on SUPERVISOR_SAMPLE_PERCENT % of calls, rest shadow
#   enforce = block/review per policy (flip to this after shadow metrics look good)
SUPERVISOR_ENFORCEMENT_MODE=shadow
SUPERVISOR_SAMPLE_PERCENT=10
# Admin token (only needed for one-time registration, not at runtime)
SUPERVISOR_ADMIN_TOKEN=
"""

CI_WORKFLOW = """name: runtime-supervisor

on: [pull_request]

jobs:
  check-supervision:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - name: Rescan repo
        run: |
          uv run --with supervisor-discover supervisor-discover scan --dry-run > /tmp/current-findings.json
      - name: Diff against committed findings
        run: |
          diff -u runtime-supervisor/findings.json /tmp/current-findings.json || {
            echo "::error::Unsupervised call-sites changed. Re-run `supervisor-discover scan` locally and commit the updated runtime-supervisor/ directory."
            exit 1
          }
"""
