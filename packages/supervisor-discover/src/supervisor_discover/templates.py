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

Cada sección abajo sigue la misma estructura:

- 🔴 **Problema:** qué puede salir mal si no se supervisa.
- 📍 **En tu repo:** dónde está detectado (archivos específicos).
- ✅ **La solución:** el wrap pattern + la policy que aplica.

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
#
# Each tier is rendered as three labelled sections + an optional technical
# footnote (where OWASP refs, policy YAML names, and other jargon go):
#
#   🔴 **Problema:**   what can go wrong in plain dev English
#   📍 **En tu repo:** count + top-3 files (injected dynamically)
#   ✅ **La solución:** the concrete ask (wrap pattern + policy name)
#   (footnote)         OWASP refs, policy name, compliance refs
#
# Keys:
#   problem              prose, no OWASP / action_type jargon
#   in_your_repo_prefix  leading sentence before the top-3 files
#   solution             wrap pattern + policy ref
#   technical_footnote   refs and policy YAML names — optional
TIER_COPY = {
    "money": {
        "title": "Money movement",
        "problem": (
            "Tu agente puede iniciar refunds, charges, subscriptions o payouts. "
            "Sin supervisión, un prompt injection puede disparar un movimiento de "
            "plata que nadie autorizó."
        ),
        "in_your_repo_prefix": (
            "{total} call-site(s) que mueven dinero sin pasar por el supervisor."
        ),
        "solution": (
            "Wrappear cada call-site con `@supervised('payment')` (o `refund`). "
            "La policy `payment.base.v1` ya enforce-a hard-cap en amount, velocity "
            "por customer, y bloquea si la cuenta bancaria cambió en las últimas 24h."
        ),
        "technical_footnote": (
            "_Policies: `payment.base.v1` y `refund.base.v1`. Detectores activos: "
            "prompt injection, jailbreak. Ref: OWASP LLM Top 10 (LLM01, LLM10)._"
        ),
    },
    "real_world_actions": {
        "title": "Real-world actions",
        "problem": (
            "Tu agente puede actuar en el mundo real: llamar por teléfono, mandar "
            "SMS/email, postear en Slack, crear eventos de calendario, escribir o "
            "borrar archivos, ejecutar comandos. Cada uno es una consecuencia "
            "irreversible si un prompt injection controla los args."
        ),
        "in_your_repo_prefix": (
            "{total} call-site(s) donde el agente actúa en el mundo real."
        ),
        "solution": (
            "Wrappear cada call-site con `@supervised('tool_use')`. Los stubs "
            "copy-paste están en `stubs/py/` y `stubs/ts/`. La policy `tool_use.base.v1` "
            "requiere tool name explícito, caps prompt length, y bloquea namespaces "
            "privilegiados (shell, fs.delete, network.raw)."
        ),
        "technical_footnote": (
            "_Policy: `tool_use.base.v1`. Detectores activos: prompt injection, "
            "jailbreak, loops / prompts gigantes. Ref: OWASP LLM Top 10 (LLM01, LLM06, LLM10)._"
        ),
    },
    "customer_data": {
        "title": "Customer data",
        "problem": (
            "El agente puede modificar tablas de clientes directamente (users, "
            "accounts, customers, orders). Un `DELETE FROM users` sin `WHERE`, "
            "un `UPDATE` que cambie email + phone + password a la vez — ambos "
            "son acciones irreversibles que hoy corren sin supervisión."
        ),
        "in_your_repo_prefix": (
            "{total} mutación(es) sobre tablas con nombres de clientes (users / "
            "accounts / customers / orders)."
        ),
        "solution": (
            "Wrappear cada mutación con `@supervised('account_change')` o "
            "`data_access` según aplique. Las policies cap scope (tenant_id "
            "requerido, row_limit, columnas PII bloqueadas) y dejan audit trail "
            "con cadena hash para cumplimiento."
        ),
        "technical_footnote": (
            "_Policies: `account_change.base.v1`, `data_access.base.v1`. Audit "
            "trail con hash-chain. Ref: OWASP LLM Top 10 (LLM02), cumplimiento: GDPR, SOC2._"
        ),
    },
    "llm": {
        "title": "LLM tool-use",
        "problem": (
            "Tu agente llama al LLM sin gating. Prompt injection (alguien escribió "
            "'ignore previous instructions' en un ticket), jailbreak del guardrail "
            "del modelo, o un loop que quema tokens — hoy todo pasa sin intervención."
        ),
        "in_your_repo_prefix": (
            "{total} invocación(es) de LLM SDKs (openai / anthropic / langchain / "
            "llama_index)."
        ),
        "solution": (
            "Wrappear las llamadas con `@supervised('tool_use')`. El supervisor "
            "valida que el prompt no supere 50k chars (loop de consumo), que el tool "
            "name esté declarado (rate-limit + audit), y corre los detectores de "
            "ataques típicos a LLMs."
        ),
        "technical_footnote": (
            "_Policy: `tool_use.base.v1`. Detectores: prompt injection, jailbreak, "
            "fugas de datos, capacidades fuera del scope, loops / prompts gigantes. "
            "Ref: OWASP LLM Top 10 (LLM01, LLM02, LLM06, LLM08, LLM10)._"
        ),
    },
    "general": {
        "title": "General / informational",
        "problem": (
            "Estos hallazgos son informativos: HTTP routes y cron schedules que "
            "mapean la superficie del repo pero no mueven dinero ni tocan datos "
            "críticos directamente. No necesitan stub — pero importan para saber "
            "qué lógica queda sin supervisar todavía."
        ),
        "in_your_repo_prefix": (
            "{total} hallazgo(s) informativo(s) (HTTP routes, cron schedules, otros)."
        ),
        "solution": (
            "N/A en esta fase. El supervisor no gatea la route ni el cron — gatea "
            "las tools que se ejecutan **adentro** de ellos. Una siguiente iteración "
            "va a poder gatear cron jobs con ejecución idempotente y rate-limits "
            "por route."
        ),
        "technical_footnote": "",
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
