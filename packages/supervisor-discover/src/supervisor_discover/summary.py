"""Rule-based repo summary.

Aggregates scanner signals into a plain-language briefing for the top of
the report. No LLM — every fact comes from what the scanners already
observed, so the summary is reproducible and cheap.

The LLM refine pass (--refine against Claude) is deferred; this module
is the deterministic baseline that ships every scan.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .findings import Finding

# Table names that usually mean PII or money — flagged so the summary can
# tell the reader "your repo touches sensitive tables" even if policies
# haven't been written for the app's specific schema yet.
_SENSITIVE_TABLE_HINTS = {
    "users", "user", "customers", "customer", "accounts", "account",
    "orders", "order", "payments", "payment", "invoices", "invoice",
    "subscriptions", "subscription", "transactions", "transaction",
    "profiles", "profile", "wallets", "wallet", "cards", "card",
    "sessions", "session", "auth_tokens", "api_keys",
}

# Stripe method families → human-readable capability labels.
_STRIPE_CAPABILITY = {
    "refund": "refunds",
    "refunds": "refunds",
    "charge": "charges",
    "paymentintent": "payments",
    "payout": "payouts",
    "transfer": "transfers",
    "subscription": "subscriptions",
    "subscriptionitem": "subscriptions",
    "checkout": "checkout",
    "invoice": "invoices",
    "customer": "customer-mgmt",
}

# LLM root module → brand. `.get()` covers aliases resolved by _imports.
_LLM_BRAND = {
    "anthropic": "Anthropic Claude",
    "openai": "OpenAI",
    "langchain": "LangChain",
    "langchain_core": "LangChain",
    "langchain_community": "LangChain",
    "llama_index": "LlamaIndex",
    "llama_cpp": "llama.cpp (local)",
}

# Real-world actions — the `scanner` name → human-readable capability label.
# Used for the top-of-report summary so the reader sees at a glance what the
# agent can DO (beyond just reading and computing).
_REAL_WORLD_CAPABILITY: dict[str, str] = {
    "voice-actions": "voice / telephony",
    "messaging": "messaging (slack / discord / sms)",
    "email-sends": "email sends",
    "calendar-actions": "calendar events",
    "fs-shell": "filesystem / shell exec",
    "media-gen": "generative media",
}


@dataclass(frozen=True)
class RepoSummary:
    frameworks: list[str] = field(default_factory=list)
    http_routes: int = 0
    payment_integrations: dict[str, list[str]] = field(default_factory=dict)
    llm_providers: list[str] = field(default_factory=list)
    # capability label → list of unique providers. e.g.:
    #   {"voice / telephony": ["twilio", "elevenlabs"],
    #    "calendar events": ["google"]}
    real_world_actions: dict[str, list[str]] = field(default_factory=dict)
    db_tables_touched: list[str] = field(default_factory=list)
    sensitive_tables: list[str] = field(default_factory=list)
    scheduled_jobs: int = 0
    total_findings: int = 0
    one_liner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _stripe_capability_from_method(method: str) -> str | None:
    """E.g. `stripe.Subscription.modify` → "subscriptions"."""
    parts = method.lower().split(".")
    if len(parts) < 2 or parts[0] != "stripe":
        return None
    return _STRIPE_CAPABILITY.get(parts[1])


def build_summary(findings: list[Finding]) -> RepoSummary:
    frameworks_seen: Counter[str] = Counter()
    http_count = 0
    payments: dict[str, set[str]] = {}
    llms: set[str] = set()
    tables: Counter[str] = Counter()
    scheduled = 0
    # capability label → set of providers detected for that capability
    rwa: dict[str, set[str]] = {}

    for f in findings:
        scanner = f.scanner
        extra = f.extra or {}

        if scanner == "http-routes":
            http_count += 1
            fw = extra.get("framework")
            # Skip "unknown" — the http-routes scanner emits it when its
            # heuristics can't classify; it's noise in the summary.
            if isinstance(fw, str) and fw and fw.lower() != "unknown":
                frameworks_seen[fw] += 1

        elif scanner == "payment-calls":
            vendor = (extra.get("vendor") or "").lower()
            method = extra.get("method") or f.snippet
            if not vendor:
                continue
            cap = _stripe_capability_from_method(method) if vendor == "stripe" else None
            payments.setdefault(vendor, set())
            if cap:
                payments[vendor].add(cap)

        elif scanner == "llm-calls":
            method = (extra.get("method") or f.snippet or "").lower()
            sdk = extra.get("sdk") or method.split(".")[0] if method else None
            brand = _LLM_BRAND.get(str(sdk).lower()) if sdk else None
            if brand:
                llms.add(brand)

        elif scanner == "db-mutations":
            t = extra.get("table") or extra.get("model")
            if isinstance(t, str) and t:
                tables[t.lower()] += 1

        elif scanner == "cron-schedules":
            scheduled += 1

        elif scanner in _REAL_WORLD_CAPABILITY:
            capability = _REAL_WORLD_CAPABILITY[scanner]
            # `provider` for SDK-based scanners; `family` for fs-shell (fs-delete/
            # fs-write/shell-exec) so the summary reflects what kind of OS access.
            provider = extra.get("provider") or extra.get("family") or scanner
            rwa.setdefault(capability, set()).add(str(provider).lower())

    sensitive = sorted(t for t in tables if t in _SENSITIVE_TABLE_HINTS)
    all_tables = sorted(tables)
    payment_integrations = {k: sorted(v) for k, v in payments.items()}
    real_world_actions = {k: sorted(v) for k, v in rwa.items()}

    # Pick the most common framework as primary; keep others as extras.
    primary_fw = [fw for fw, _ in frameworks_seen.most_common()]

    return RepoSummary(
        frameworks=primary_fw,
        http_routes=http_count,
        payment_integrations=payment_integrations,
        llm_providers=sorted(llms),
        real_world_actions=real_world_actions,
        db_tables_touched=all_tables,
        sensitive_tables=sensitive,
        scheduled_jobs=scheduled,
        total_findings=len(findings),
        one_liner=_one_liner(primary_fw, payment_integrations, llms, real_world_actions, sensitive),
    )


# Scanner-emitted framework keys → canonical brand casing. Produces
# prose-readable names in the headline ("Next.js" not "next-app-router").
_FRAMEWORK_LABELS = {
    "fastapi": "FastAPI", "flask": "Flask", "django": "Django",
    "starlette": "Starlette", "aiohttp": "aiohttp", "quart": "Quart",
    "tornado": "Tornado", "sanic": "Sanic", "bottle": "Bottle",
    "pyramid": "Pyramid",
    "express": "Express", "nest": "NestJS", "nestjs": "NestJS",
    "koa": "Koa", "hono": "Hono", "fastify": "Fastify",
    "next": "Next.js", "next-app-router": "Next.js", "next-pages": "Next.js",
    "remix": "Remix", "sveltekit": "SvelteKit", "astro": "Astro",
}

_RWA_PRIORITY = [
    "voice / telephony",
    "email sends",
    "messaging (slack / discord / sms)",
    "filesystem / shell exec",
    "generative media",
    "calendar events",
]


def _es_join(items: list[str]) -> str:
    """Natural Spanish join: ['a','b','c'] → 'a, b y c'."""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} y {items[1]}"
    return f"{', '.join(items[:-1])} y {items[-1]}"


def _one_liner(
    frameworks: list[str],
    payments: dict[str, list[str]],
    llms: set[str],
    real_world_actions: dict[str, list[str]],
    sensitive_tables: list[str],
) -> str:
    """Human-readable headline, derived — not LLM-written."""
    fw_label: str | None = None
    if frameworks:
        key = frameworks[0].lower()
        fw_label = _FRAMEWORK_LABELS.get(key, frameworks[0].capitalize())

    features: list[str] = []

    if real_world_actions:
        caps = sorted(real_world_actions.keys())
        ordered = [c for c in _RWA_PRIORITY if c in caps] + [c for c in caps if c not in _RWA_PRIORITY]
        features.append(f"acciones reales ({', '.join(ordered[:2])})")

    if payments:
        vendors = sorted(v.capitalize() for v in payments.keys())
        features.append(f"cobros vía {_es_join(vendors)}")

    if llms:
        features.append("agentes LLM")

    if sensitive_tables:
        features.append("datos de clientes")

    if not fw_label and not features:
        return "repo sin integraciones críticas detectadas"
    if fw_label and features:
        return f"una app **{fw_label}** con {_es_join(features)}"
    if fw_label:
        return f"una app **{fw_label}**"
    return f"un repo con {_es_join(features)}"


def render_markdown(summary: RepoSummary) -> str:
    """Markdown block that goes at the top of report.md."""
    lines: list[str] = ["## Qué es este repo", ""]

    if summary.frameworks:
        fw_str = " + ".join(f"**{fw}**" for fw in summary.frameworks)
        lines.append(f"Stack detectado: {fw_str} ({summary.http_routes} routes HTTP).")
    elif summary.http_routes:
        lines.append(f"HTTP surface: {summary.http_routes} routes (framework no reconocido).")
    else:
        lines.append("Sin endpoints HTTP detectados.")
    lines.append("")

    if summary.payment_integrations:
        parts: list[str] = []
        for vendor, caps in summary.payment_integrations.items():
            v = vendor.capitalize()
            if caps:
                parts.append(f"**{v}** ({', '.join(caps)})")
            else:
                parts.append(f"**{v}**")
        lines.append(f"Integraciones de pago: {', '.join(parts)}.")
    else:
        lines.append("Sin SDKs de pago detectados.")

    if summary.llm_providers:
        lines.append(f"LLM providers: {', '.join(f'**{p}**' for p in summary.llm_providers)}.")
    else:
        lines.append("Sin LLM SDKs detectados.")

    if summary.real_world_actions:
        parts: list[str] = []
        for capability, providers in summary.real_world_actions.items():
            providers_str = ", ".join(providers)
            parts.append(f"**{capability}** ({providers_str})")
        lines.append(f"Acciones reales del agente: {'; '.join(parts)}.")

    if summary.scheduled_jobs:
        lines.append(f"Scheduled jobs: {summary.scheduled_jobs} crons/tareas programadas.")

    lines.append("")
    if summary.sensitive_tables:
        lines.append(
            "Tablas con nomenclatura sensible (users/orders/customers/...): "
            + ", ".join(f"`{t}`" for t in summary.sensitive_tables)
            + "."
        )
    elif summary.db_tables_touched:
        lines.append(f"Tablas tocadas: {len(summary.db_tables_touched)}.")

    lines.append("")
    lines.append(f"En una frase: {summary.one_liner}.")
    lines.append("")
    return "\n".join(lines)


def render_cli_stdout(summary: RepoSummary) -> list[str]:
    """Short lines for the CLI, printed before the tier summary. 3 lines when
    the repo has no real-world actions; 4 when it does — we always want the
    operator to see what kind of side-effects the agent can produce."""
    out: list[str] = []
    fw = " + ".join(summary.frameworks) if summary.frameworks else "framework no reconocido"
    pay = (
        ", ".join(f"{k} ({', '.join(v)})" if v else k for k, v in summary.payment_integrations.items())
        if summary.payment_integrations else "—"
    )
    llm = ", ".join(summary.llm_providers) if summary.llm_providers else "—"
    out.append(f"  stack: {fw}  ·  HTTP routes: {summary.http_routes}")
    out.append(f"  payments: {pay}")
    out.append(f"  LLM: {llm}  ·  crons: {summary.scheduled_jobs}")
    if summary.real_world_actions:
        # Collapsed one-liner: "voice (twilio, elevenlabs), calendar (google)"
        parts = [
            f"{cap.split(' ')[0]} ({', '.join(providers)})"
            for cap, providers in summary.real_world_actions.items()
        ]
        out.append(f"  actions: {' · '.join(parts)}")
    return out
