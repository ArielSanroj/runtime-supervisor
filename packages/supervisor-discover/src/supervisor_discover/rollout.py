"""Render ROLLOUT.md tailored to the scanned repo.

Sibling of `summary.render_markdown` (which produces `report.md`). Both
consume the same `RepoSummary` + `findings` and emit human-readable
markdown. Keeping them in separate modules because the report describes
what was found, while the rollout prescribes what to do with it — two
different writing jobs.
"""
from __future__ import annotations

from typing import Literal

from .classifier import TIER_ORDER, Tier, group_by_risk_tier
from .findings import Finding
from .summary import RepoSummary
from .templates import TIER_COPY

Stack = Literal["python", "typescript", "mixed", "unknown"]
Pacing = Literal["none", "minimal", "small", "large"]

_PY_FRAMEWORKS = {
    "flask", "fastapi", "django", "starlette", "aiohttp",
    "quart", "tornado", "sanic", "bottle", "pyramid",
}
_TS_FRAMEWORKS = {
    "express", "nest", "nestjs", "koa", "hono", "fastify",
    "remix", "sveltekit", "astro",
}

# Volume floor before advancing from one phase to the next. "1 week without
# false-positives" is meaningless if there's no traffic — these numbers
# make "enough observation to trust the signal" explicit.
_MIN_CALLS_BY_TIER: dict[Tier, int] = {
    "money": 20,
    "real_world_actions": 20,  # voice/email/slack/shell — irreversible, be conservative
    "llm": 30,
    "customer_data": 50,
    "general": 0,
}


def _detect_stack(summary: RepoSummary, findings: list[Finding]) -> Stack:
    """Decide whether to show Python or TypeScript code examples.
    Framework names drive this first, file extensions are the fallback."""
    fw = {f.lower() for f in summary.frameworks}
    has_py = any(f in _PY_FRAMEWORKS for f in fw)
    has_ts = any(f in _TS_FRAMEWORKS or f.startswith("next") for f in fw)

    if has_py and has_ts:
        return "mixed"
    if has_py:
        return "python"
    if has_ts:
        return "typescript"

    py = sum(1 for f in findings if f.file.endswith(".py"))
    ts = sum(1 for f in findings if f.file.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")))
    if py > ts * 2:
        return "python"
    if ts > py * 2:
        return "typescript"
    if py and ts:
        return "mixed"
    return "unknown"


def _pacing(summary: RepoSummary, findings: list[Finding]) -> Pacing:
    """How long the rollout should be, based on risk surface size.

    none    → no rollout needed (nothing high-risk to gate)
    minimal → one shadow phase, no advancement (too little to measure)
    small   → two phases (shadow → enforce)
    large   → three phases (shadow → sample → enforce per tier)

    All action tiers count toward criticality, not just money + llm. A repo
    with 24 real-world-actions HIGH (voice/email/shell) needs a full rollout
    just as much as one with 2 payment findings — the earlier version missed
    that because it only summed money_high + llm_high.
    """
    if not findings:
        return "none"

    buckets = group_by_risk_tier(findings)
    high_by_tier = {
        tier: sum(1 for f in buckets[tier] if f.confidence == "high")
        for tier in ("money", "real_world_actions", "llm", "customer_data")
    }
    total_high = sum(high_by_tier.values())

    if total_high == 0:
        return "minimal"
    if total_high >= 3 or summary.total_findings >= 100:
        return "large"
    return "small"


_CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


def _tier_confidence_rank(items: list[Finding]) -> int:
    """Max confidence in a tier (2=high, 1=medium, 0=low/none)."""
    return max((_CONFIDENCE_RANK[f.confidence] for f in items), default=0)


def _active_tiers(findings: list[Finding]) -> list[Tier]:
    """Tiers that have at least one high/medium finding, ordered by max
    confidence (descending) so enforce progression targets the sharpest
    risk first. Ties fall back to TIER_ORDER (money > customer > llm).
    `general` is never a phase driver (informational only)."""
    buckets = group_by_risk_tier(findings)
    active: list[tuple[Tier, int, int]] = []
    for tier in TIER_ORDER:
        if tier == "general":
            continue
        items = buckets[tier]
        if any(f.confidence in ("high", "medium") for f in items):
            rank = _tier_confidence_rank(items)
            active.append((tier, rank, TIER_ORDER.index(tier)))
    active.sort(key=lambda x: (-x[1], x[2]))
    return [t for t, _, _ in active]


def _shadow_config_block(stack: Stack) -> str:
    """Code snippet + env-var note. Emphasize env var as the operational
    lever — it works stack-agnostic and doesn't need a code redeploy."""
    env_note = (
        "`configure()` sin argumentos ya lee `SUPERVISOR_ENFORCEMENT_MODE` del "
        "entorno y defaultea a shadow. Para cambiar de modo (shadow/sample/enforce) "
        "en runtime, cambia la env var y reinicia — no requiere redeploy de código."
    )
    if stack == "typescript":
        code = (
            "```typescript\n"
            'import { configure } from "@runtime-supervisor/guards";\n'
            "configure();\n"
            "```"
        )
    elif stack == "mixed":
        code = (
            "Python:\n"
            "```python\n"
            "import supervisor_guards as sg\n"
            "sg.configure()\n"
            "```\n\n"
            "TypeScript:\n"
            "```typescript\n"
            'import { configure } from "@runtime-supervisor/guards";\n'
            "configure();\n"
            "```"
        )
    else:
        code = (
            "```python\n"
            "import supervisor_guards as sg\n"
            "sg.configure()\n"
            "```"
        )
    return f"{code}\n\n{env_note}"


def _surface_block(summary: RepoSummary, findings: list[Finding], stack: Stack) -> str:
    lines: list[str] = ["## Superficie detectada", ""]

    stack_label = {
        "python": "Python",
        "typescript": "TypeScript/JavaScript",
        "mixed": "Python + TypeScript",
        "unknown": "no identificado por framework",
    }[stack]
    fw_str = ", ".join(summary.frameworks) if summary.frameworks else "—"
    lines.append(f"- **Stack:** {stack_label} ({fw_str})")

    if summary.payment_integrations:
        parts = []
        for vendor, caps in summary.payment_integrations.items():
            parts.append(f"{vendor.capitalize()} ({', '.join(caps)})" if caps else vendor.capitalize())
        lines.append(f"- **Pagos:** {', '.join(parts)}")

    if summary.llm_providers:
        lines.append(f"- **LLMs:** {', '.join(summary.llm_providers)}")

    buckets = group_by_risk_tier(findings)
    tier_lines: list[str] = []
    for tier in TIER_ORDER:
        items = buckets[tier]
        if tier == "general" or not items:
            continue
        high = sum(1 for f in items if f.confidence == "high")
        med = sum(1 for f in items if f.confidence == "medium")
        if high == 0 and med == 0:
            continue
        title = TIER_COPY[tier]["title"]
        tier_lines.append(f"  - {title}: {high} high / {med} medium")
    if tier_lines:
        lines.append("- **Call-sites a gatear:**")
        lines.extend(tier_lines)

    lines.append("")
    return "\n".join(lines)


def _exit_criteria(tier: Tier) -> str:
    """Per-tier exit criteria — volume floor + quality gate."""
    floor = _MIN_CALLS_BY_TIER[tier]
    title = TIER_COPY[tier]["title"]
    return (
        f"≥ {floor} llamadas de {title.lower()} observadas Y "
        "`estimated_false_positive_rate` < 5% Y `would_block_in_shadow` "
        "no incluye paths legítimos"
    )


def _metrics_block() -> str:
    """Short pointer block — the tier-specific metrics live inside each phase
    now. This just tells the reader where to look."""
    return (
        "## Dónde mirar las métricas\n\n"
        "- **Dashboard local:** `http://localhost:3099/dashboard` si instalaste con "
        "`ac start`. Entries recientes, decisiones por tier, casos pendientes de "
        "review. Refresh cada 5s.\n"
        "- **API programática:** `GET ${SUPERVISOR_BASE_URL}/v1/metrics/enforcement?window=24h` "
        "para CI, dashboards externos, o cuando necesites la data en JSON.\n\n"
        "Cada fase arriba define qué métricas mirar en ese momento específico "
        "— mira el 📊 de cada fase activa.\n"
    )


def _rollback_block() -> str:
    return (
        "## Rollback\n\n"
        "Escape hatch sin redeploy:\n\n"
        "```bash\n"
        "export SUPERVISOR_ENFORCEMENT_MODE=shadow\n"
        "# restart el proceso; los guards vuelven a observar sin bloquear\n"
        "```\n\n"
        "Si el problema es el guard mismo (errores de red, latencia al supervisor), "
        "configura `SUPERVISOR_ENFORCEMENT_MODE=off` y los guards hacen bypass completo. "
        "El código sigue compilando y pasando tests — sólo deja de evaluar.\n"
    )


_CRITERIA_GATED_NOTE = (
    "La fase termina cuando se cumplen los criterios de salida — no se "
    "mide en semanas de calendario. Un repo con poco tráfico puede tardar "
    "más en acumular el volumen mínimo; uno con tráfico alto avanza en días."
)


def _phase_shadow(n: int, active: list[Tier], stack: Stack) -> str:
    tiers_label = ", ".join(TIER_COPY[t]["title"].lower() for t in active) or "todos los call-sites relevantes"
    exit_lines = "\n".join(f"  - {TIER_COPY[t]['title']}: {_exit_criteria(t)}" for t in active)
    return (
        f"## Fase {n} — Shadow\n\n"
        f"🎯 **Qué es esta fase:**\n"
        f"El supervisor observa cada llamada y registra qué HABRÍA hecho, pero no "
        f"bloquea. Seguro para deployar en day 1.\n\n"
        f"🔧 **Qué haces:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=shadow` en el env.\n"
        f"2. Bootstrap en el arranque:\n\n"
        f"{_shadow_config_block(stack)}\n\n"
        f"3. Pega los stubs de `stubs/` en tu código — cubren {tiers_label}.\n"
        f"4. Deploy normal. Nada bloquea.\n\n"
        f"📊 **Qué mides:**\n"
        f"- `would_block_in_shadow` — cuántas llamadas habría bloqueado (target: no incluir paths legítimos).\n"
        f"- `estimated_false_positive_rate` — target < 5%.\n"
        f"- Si `would_block_in_shadow` incluye paths legítimos → ajustar el YAML "
        f"en `policies/` o excluir ese call-site de la policy.\n\n"
        f"✅ **Cuándo avanzas a la fase siguiente** (todos deben cumplirse):\n"
        f"{exit_lines}\n\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _phase_sample(n: int, primary: Tier) -> str:
    title = TIER_COPY[primary]["title"].lower()
    return (
        f"## Fase {n} — Sample 10% en {title}\n\n"
        f"🎯 **Qué es esta fase:**\n"
        f"Enforce-a el 10% de las llamadas de {title}; el resto de los tiers sigue "
        f"en shadow. Primera fase donde el supervisor puede bloquear tráfico real, "
        f"pero acotado.\n\n"
        f"🔧 **Qué haces:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=sample` + `SUPERVISOR_SAMPLE_PERCENT=10` en el env.\n"
        f"2. Reiniciar el proceso — los guards leen la env al arrancar.\n"
        f"3. Los stubs de otros tiers mantienen `on_review=\"shadow\"` (no los toques).\n\n"
        f"📊 **Qué mides:**\n"
        f"- `actually_blocked` — cuántas bloqueó el supervisor de verdad.\n"
        f"- `estimated_false_positive_rate` — target < 5%.\n"
        f"- Si aparecen falsos positivos → volver a shadow (`SUPERVISOR_ENFORCEMENT_MODE=shadow`) "
        f"y ajustar la policy antes de reintentar.\n\n"
        f"✅ **Cuándo avanzas a enforce completo:**\n"
        f"  - `actually_blocked > 0` (sabes que el guard está conectado)\n"
        f"  - FP rate < 5%\n"
        f"  - ≥ {_MIN_CALLS_BY_TIER[primary]} sampled calls\n\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _phase_enforce(n: int, active: list[Tier]) -> str:
    progression = " → ".join(TIER_COPY[t]["title"] for t in active)
    return (
        f"## Fase {n} — Enforce progresivo\n\n"
        f"🎯 **Qué es esta fase:**\n"
        f"El supervisor bloquea por policy en los tiers activos. Progresión "
        f"sugerida (mayor severidad primero): **{progression}**.\n\n"
        f"🔧 **Qué haces:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=enforce` en el env.\n"
        f"2. Para el tier actual en la progresión, cambiar sus stubs a `on_review=\"block\"` "
        f"(poll por decisión de revisor humano). Los demás tiers mantienen `on_review=\"shadow\"` "
        f"hasta llegarles el turno.\n"
        f"3. Esperar a que el tier actual mantenga FP rate < 5% antes de pasar al siguiente.\n\n"
        f"📊 **Qué mides:**\n"
        f"- `actually_blocked` por tier — estable durante 48h antes de pasar al siguiente.\n"
        f"- `estimated_false_positive_rate` por tier — target < 5%.\n"
        f"- `latency_ms.p95 / p99` — target p95 < 200ms, p99 < 500ms.\n\n"
        f"✅ **Rollback si algo sale mal:**\n"
        f"Si en cualquier tier el FP rate supera 5% → `SUPERVISOR_ENFORCEMENT_MODE=shadow` "
        f"ese tier, ajustar la policy, y retomar desde Fase 1 o 2 para ese tier específico. "
        f"Los demás tiers ya enforzados quedan como están.\n\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _short_rollout(summary: RepoSummary, findings: list[Finding], stack: Stack) -> str:
    """For minimal repos — skip the multi-phase plan."""
    active = _active_tiers(findings)
    tiers_label = ", ".join(TIER_COPY[t]["title"].lower() for t in active) if active else "los call-sites informativos"

    lines = [
        f"# Rollout playbook — {summary.one_liner}",
        "",
        "Superficie chica: no hay call-sites HIGH en ningún tier, "
        "así que el rollout se colapsa a una fase de observación. "
        "Cuando aparezcan findings HIGH (nuevas integraciones, call-sites agregados), "
        "re-escaneá y el playbook extendido se regenera solo.",
        "",
        _surface_block(summary, findings, stack),
        "## Fase única — Shadow indefinido",
        "",
        "Setup: `SUPERVISOR_ENFORCEMENT_MODE=shadow`. Bootstrap en el arranque:",
        "",
        _shadow_config_block(stack),
        "",
        "Qué hacer:",
        f"1. Pega los stubs (cubren {tiers_label}).",
        "2. Deploy normal.",
        "3. Re-escanea (`supervisor-discover scan`) cuando agregues integraciones nuevas "
        "(payments, LLM providers, jobs programados). Si aparecen call-sites HIGH, "
        "regenera este ROLLOUT.md y sigue el playbook extendido.",
        "",
        _metrics_block(),
        _rollback_block(),
    ]
    return "\n".join(lines)


def _empty_rollout(summary: RepoSummary) -> str:
    return (
        f"# Rollout playbook — {summary.one_liner}\n\n"
        "El scan no encontró call-sites que justifiquen un rollout por fases.\n\n"
        "Re-escanea cuando:\n"
        "- Agregues un SDK de pagos (Stripe, Adyen, etc.)\n"
        "- Agregues un LLM provider (OpenAI, Anthropic, etc.)\n"
        "- Agregues mutaciones directas a tablas sensibles (users/orders/customers/...)\n\n"
        "El supervisor no tiene nada para gatear en este repo hoy. Dejalo instalado "
        "con `SUPERVISOR_ENFORCEMENT_MODE=shadow` para que futuros cambios aparezcan "
        "en el próximo scan.\n"
    )


def render_rollout_md(summary: RepoSummary, findings: list[Finding]) -> str:
    """Produce ROLLOUT.md content tailored to the scanned repo.

    Public entry point. `generator.generate` calls this instead of writing
    a static template.
    """
    pacing = _pacing(summary, findings)
    stack = _detect_stack(summary, findings)

    if pacing == "none":
        return _empty_rollout(summary)

    if pacing == "minimal":
        return _short_rollout(summary, findings, stack)

    active = _active_tiers(findings)
    # Primary tier for sample phase — highest-confidence active tier
    # (`_active_tiers` already returns them in that order).
    primary: Tier = active[0] if active else "customer_data"

    blocks = [
        f"# Rollout playbook — {summary.one_liner}",
        "",
        "Este playbook te lleva desde *shadow* (observar sin bloquear) hasta *enforce* "
        "(bloquear según política), midiendo volumen y falsos positivos en cada paso.",
        "",
        _surface_block(summary, findings, stack),
        _phase_shadow(1, active, stack),
    ]

    phase_n = 2
    if pacing == "large":
        blocks.append(_phase_sample(phase_n, primary))
        phase_n += 1

    blocks.append(_phase_enforce(phase_n, active))
    blocks.append(_metrics_block())
    blocks.append(_rollback_block())

    return "\n".join(blocks)
