"""Render ROLLOUT.md tailored to the scanned repo.

Sibling of `summary.render_markdown` (which produces `report.md`). Both
consume the same `RepoSummary` + `findings` and emit human-readable
markdown. Keeping them in separate modules because the report describes
what was found, while the rollout prescribes what to do with it — two
different writing jobs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .classifier import TIER_ORDER, Tier, group_by_risk_tier
from .findings import Finding
from .summary import RepoSummary
from .templates import TIER_COPY


@dataclass(frozen=True)
class Criterion:
    """One exit criterion with its repo-derived rationale.

    `rule` is the checkbox line the reader sees first ("≥ 20 llamadas observadas").
    `why` is the italic explanation directly below, **always derived from the
    repo's scan** — counts, top providers, file samples. Never hardcoded text
    that reads the same across different repos.
    """
    rule: str
    why: str

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


def _short_path(file: str) -> str:
    """Last two path segments — local copy to avoid circular imports
    with narrator.py / generator.py which have their own `_short_path`."""
    parts = file.rsplit("/", 2)
    return "/".join(parts[-2:]) if len(parts) > 1 else file


def _top_evidence_for_tier(items: list[Finding], limit: int = 2) -> list[str]:
    """Return top N file:line for a tier, ordered by confidence desc.
    Used by the 'would_block_in_shadow' rationale to cite concrete
    call-sites in the reader's repo."""
    order = {"high": 0, "medium": 1, "low": 2}
    sorted_items = sorted(items, key=lambda f: (order.get(f.confidence, 3), f.file))
    return [f"`{_short_path(f.file)}:{f.line}`" for f in sorted_items[:limit]]


def _tier_scanners(items: list[Finding]) -> list[str]:
    """Unique scanner names in a tier, stable order. Used to compose
    rationale sentences that reference 'what kind of call-sites these are'."""
    seen: set[str] = set()
    out: list[str] = []
    for f in items:
        if f.scanner not in seen:
            seen.add(f.scanner)
            out.append(f.scanner)
    return out


def _tier_providers(items: list[Finding]) -> list[str]:
    """Unique provider/family labels in a tier. Gives the rationale
    something concrete to name ('smtplib', 'twilio', 'shell-exec')."""
    seen: set[str] = set()
    out: list[str] = []
    for f in items:
        provider = str(f.extra.get("provider") or f.extra.get("family") or "")
        if provider and provider not in seen:
            seen.add(provider)
            out.append(provider)
    return out


def _fp_tolerance(count: int) -> str:
    """Human-readable '5% of N' — 'max 0-1 FP', 'max ~15 FP'."""
    tol = count * 0.05
    if tol < 1:
        return "max 0–1 falsos positivos"
    if tol < 5:
        return f"max ~{round(tol)} falsos positivos"
    return f"max ~{round(tol)} falsos positivos"


def _pluralize(count: int, singular: str, plural: str) -> str:
    """Tiny grammar helper so rationale strings don't say '1 call-sites'.
    Agreement matters when the count is derived from the repo."""
    return f"{count} {singular if count == 1 else plural}"


def _possessive_count(count: int, singular: str, plural: str) -> str:
    """Spanish possessive + count with agreement: 'tu 1 call-site' vs
    'tus 13 call-sites'. Fixes 'tus 1 call-site' voseo-like gaffe."""
    if count == 1:
        return f"tu {singular}"
    return f"tus {count} {plural}"


# ── Rationale helpers — every string here is composed from repo state ────

def _why_volume_floor(tier: Tier, items: list[Finding]) -> str:
    floor = _MIN_CALLS_BY_TIER[tier]
    count = len(items)
    title = TIER_COPY[tier]["title"].lower()
    if count == 0:
        return (
            f"el scanner no encontró call-sites en este tier, así que el umbral "
            f"mínimo de {floor} observaciones aplica sólo si aparecen nuevos "
            f"call-sites en próximos scans."
        )
    noun = _pluralize(count, "call-site", "call-sites")
    if count < floor:
        return (
            f"tu repo tiene {noun} de {title} detectado{'' if count == 1 else 's'} — poca "
            f"superficie estática. El umbral mínimo es {floor} **observaciones en "
            f"runtime** (no call-sites) porque cada call-site puede invocarse "
            f"con múltiples patrones de argumentos distintos. Necesitas ver la "
            f"variedad en runtime, no sólo el happy path."
        )
    return (
        f"tu repo tiene {noun} de {title} detectados. Con menos de "
        f"{floor} observaciones en runtime, el supervisor ve sólo una muestra "
        f"del happy path — no puedes distinguir un call-site legítimo raro de "
        f"un positivo real. Si tu tráfico es alto, cumples este criterio en horas."
    )


def _why_fp_threshold(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    title = TIER_COPY[tier]["title"].lower()
    if count == 0:
        return (
            "mientras no haya observaciones, este criterio es trivial. Aplica "
            "cuando aparezca tráfico real — más de 1 de cada 20 llamadas "
            "bloqueadas indebidamente erosiona la confianza en el supervisor."
        )
    tolerance = _fp_tolerance(count)
    possessive = _possessive_count(count, "call-site", "call-sites")
    return (
        f"sobre {possessive} de {title}, 5% = {tolerance} por "
        f"pasada del policy engine. Más que eso y el supervisor se siente como "
        f"fricción, no como protección — el equipo deja de confiar y busca "
        f"forma de desactivarlo."
    )


def _why_no_legitimate_blocks(tier: Tier, items: list[Finding]) -> str:
    title = TIER_COPY[tier]["title"].lower()
    if not items:
        return (
            "sin call-sites detectados, este criterio es preventivo. Aplica al "
            "aparecer el primer finding high/medium del tier."
        )
    top = _top_evidence_for_tier(items, limit=2)
    top_str = " · ".join(top)
    more = f" + {len(items) - len(top)} más" if len(items) > len(top) else ""
    # Singular vs plural intro
    if len(top) == 1 and not more:
        intro = f"el call-site de {title} en tu repo es {top_str}"
    else:
        intro = f"los top call-sites de {title} en tu repo son {top_str}{more}"
    return (
        f"{intro}. "
        f"Si alguno aparece como \"habría bloqueado\" en shadow, al flipar a "
        f"enforce rompes ese flow en prod. Se arregla antes editando el YAML "
        f"de `policies/` o excluyendo el call-site con `skip_policies`."
    )


def _why_actually_blocked(tier: Tier, items: list[Finding]) -> str:
    title = TIER_COPY[tier]["title"].lower()
    providers = _tier_providers(items)
    if providers:
        providers_str = ", ".join(f"`{p}`" for p in providers[:3])
        tail = f" (sobre tus providers detectados: {providers_str})"
    else:
        tail = ""
    return (
        f"si nunca bloqueó durante sample, o el guard no está conectado{tail}, "
        f"o no hay tráfico que matchee la policy. En cualquier caso, pasar a "
        f"enforce de {title} es ciego — no sabes qué va a pasar."
    )


def _why_fp_in_sample(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    title = TIER_COPY[tier]["title"].lower()
    if count == 0:
        return (
            "aunque no haya call-sites detectados, la policy podría matchear "
            "tráfico futuro — mantener el umbral protege de sobre-enforzar "
            "cuando aparezca."
        )
    return (
        f"al muestrear 10% de {title}, cualquier FP es visible en producción "
        f"real (no en shadow). Sobre {_possessive_count(count, 'call-site detectado', 'call-sites detectados')}, un FP "
        f"rate sostenido > 5% significa que algún flow legítimo está siendo "
        f"bloqueado y nadie en el equipo sabe por qué. Pausar y ajustar."
    )


def _why_sample_call_count(tier: Tier, items: list[Finding]) -> str:
    floor = _MIN_CALLS_BY_TIER[tier]
    title = TIER_COPY[tier]["title"].lower()
    return (
        f"≥ {floor} llamadas sampleadas te da cobertura estadística del 10% "
        f"sobre {title}. Menos que eso y el enforce completo es una apuesta "
        f"— no tienes evidencia de que la policy sostiene el ritmo real."
    )


def _why_latency_targets(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    if count == 0:
        tail = ""
    else:
        tail = (
            f" Sobre {_possessive_count(count, 'call-site de este tier', 'call-sites de este tier')}, p99 > 500ms se "
            f"percibe como timeout en cualquier flow interactivo."
        )
    return (
        "el supervisor corre en el path crítico. p95 > 200ms significa que "
        "el 5% más lento de las llamadas agrega latencia perceptible al "
        f"usuario; los usuarios perciben al supervisor como \"lentitud\", no "
        f"como protección.{tail}"
    )


def _exit_criteria(tier: Tier, findings: list[Finding]) -> list[Criterion]:
    """Per-tier exit criteria for the Shadow phase — each rule paired with
    a repo-derived 'por qué'. Takes findings (not just tier) so the rationale
    can reference real counts, top providers, and evidence file:line."""
    floor = _MIN_CALLS_BY_TIER[tier]
    tier_items = group_by_risk_tier(findings)[tier]
    return [
        Criterion(
            rule=f"≥ {floor} llamadas observadas en runtime",
            why=_why_volume_floor(tier, tier_items),
        ),
        Criterion(
            rule="`estimated_false_positive_rate` < 5%",
            why=_why_fp_threshold(tier, tier_items),
        ),
        Criterion(
            rule="`would_block_in_shadow` no incluye paths legítimos",
            why=_why_no_legitimate_blocks(tier, tier_items),
        ),
    ]


def _sample_exit_criteria(tier: Tier, findings: list[Finding]) -> list[Criterion]:
    """Sample → Enforce transition criteria. Different from shadow exit
    because now we've seen actual blocks, so the rationale changes."""
    tier_items = group_by_risk_tier(findings)[tier]
    return [
        Criterion(
            rule="`actually_blocked > 0`",
            why=_why_actually_blocked(tier, tier_items),
        ),
        Criterion(
            rule="`estimated_false_positive_rate` < 5%",
            why=_why_fp_in_sample(tier, tier_items),
        ),
        Criterion(
            rule=f"≥ {_MIN_CALLS_BY_TIER[tier]} sampled calls",
            why=_why_sample_call_count(tier, tier_items),
        ),
    ]


def _enforce_rollback_criterion(active: list[Tier], findings: list[Finding]) -> Criterion:
    """The rollback criterion applies across tiers during enforce — not a
    single-tier check. Rationale still references repo state (which tiers
    are active, what their top providers are)."""
    if not active:
        tail = ""
    else:
        tier_labels = ", ".join(TIER_COPY[t]["title"] for t in active)
        tail = f" Tiers activos en tu repo: {tier_labels}."
    return Criterion(
        rule=(
            "Si en cualquier tier enforzado el FP rate > 5% → ese tier vuelve "
            "a `shadow`, ajustar la policy, y retomar desde Fase 1 o 2 para "
            "ese tier específico."
        ),
        why=(
            "el rollback es **por tier**, no global — los demás tiers ya "
            "enforzados siguen protegiendo. Esto deja reparar una policy mal "
            "calibrada sin perder cobertura en el resto del supervisor."
            f"{tail}"
        ),
    )


def _render_criteria(criteria: list[Criterion], *, indent: str = "") -> str:
    """Render a list of Criterion as markdown checkbox + italic rationale."""
    out: list[str] = []
    for c in criteria:
        out.append(f"{indent}- [ ] {c.rule}")
        out.append(f"{indent}   _Por qué: {c.why}_")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


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


def _phase_shadow(
    n: int, active: list[Tier], stack: Stack, findings: list[Finding]
) -> str:
    tiers_label = (
        ", ".join(TIER_COPY[t]["title"].lower() for t in active)
        or "todos los call-sites relevantes"
    )
    # Exit criteria grouped by tier — each with its repo-derived "por qué".
    exit_blocks: list[str] = []
    for t in active:
        title = TIER_COPY[t]["title"]
        criteria = _exit_criteria(t, findings)
        exit_blocks.append(
            f"**{title}** — los {len(criteria)} criterios deben cumplirse:\n\n"
            + _render_criteria(criteria)
        )
    exit_section = "\n".join(exit_blocks) if exit_blocks else (
        "Sin tiers activos — re-escanea cuando agregues call-sites críticos.\n"
    )

    # Metrics bullets — each with repo-derived rationale.
    metric_lines = _render_shadow_metrics(active, findings)

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
        f"📊 **Qué mides:**\n\n"
        f"{metric_lines}\n"
        f"✅ **Cuándo avanzas a la fase siguiente:**\n\n"
        f"{exit_section}\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _render_shadow_metrics(active: list[Tier], findings: list[Finding]) -> str:
    """Compose the '📊 Qué mides' bullets for shadow phase. Each bullet
    gets a repo-derived 'por qué' inline so the reader knows why that
    metric matters for THEIR findings."""
    # Total items across active tiers — used to frame the FP-rate context.
    buckets = group_by_risk_tier(findings)
    total_active = sum(len(buckets[t]) for t in active)
    out: list[str] = []

    out.append(
        "- `would_block_in_shadow` — cuántas llamadas habría bloqueado "
        "(target: no incluir paths legítimos)."
    )
    if active:
        # Show up to 2 top paths as concrete example of what to watch.
        all_top: list[str] = []
        for t in active:
            all_top.extend(_top_evidence_for_tier(buckets[t], limit=1))
            if len(all_top) >= 2:
                break
        if all_top:
            out.append(
                f"   _Por qué: te deja construir allowlists con data real — "
                f"si {all_top[0]} aparece como 'habría bloqueado' pero es un "
                f"flow normal, ajustas la policy antes de que afecte prod._"
            )
        else:
            out.append(
                "   _Por qué: te deja construir allowlists con data real "
                "antes de enforzar._"
            )
    out.append("")

    out.append("- `estimated_false_positive_rate` — target < 5%.")
    if total_active > 0:
        out.append(
            f"   _Por qué: sobre {_possessive_count(total_active, 'call-site activo', 'call-sites activos')} "
            f"(high + medium), {_fp_tolerance(total_active)} por pasada. "
            f"Arriba de eso y el equipo percibe al supervisor como ruido._"
        )
    else:
        out.append(
            "   _Por qué: más de 1 de cada 20 llamadas bloqueadas "
            "indebidamente erosiona la confianza del equipo en el supervisor._"
        )
    out.append("")

    out.append(
        "- Si `would_block_in_shadow` incluye paths legítimos → ajustar el "
        "YAML en `policies/` o excluir ese call-site de la policy."
    )
    out.append("")
    return "\n".join(out).rstrip() + "\n"


def _phase_sample(n: int, primary: Tier, findings: list[Finding]) -> str:
    title = TIER_COPY[primary]["title"].lower()
    criteria = _sample_exit_criteria(primary, findings)

    # Repo-derived metric rationale for sample phase.
    buckets = group_by_risk_tier(findings)
    primary_items = buckets[primary]
    primary_count = len(primary_items)

    if primary_count > 0:
        actually_blocked_why = (
            f"_Por qué: de {_possessive_count(primary_count, 'call-site', 'call-sites')} de {title}, el 10% "
            f"sampleado debería tocar al menos los high-confidence "
            f"({sum(1 for f in primary_items if f.confidence == 'high')} en tu repo). "
            f"Si `actually_blocked = 0` después de días de tráfico, o el guard "
            f"no se instaló, o la policy no matchea nada real._"
        )
        fp_why = (
            f"_Por qué: ahora los bloqueos son reales — no shadow. Sobre tus "
            f"{primary_count} call-sites, {_fp_tolerance(primary_count)}. "
            f"Sobre eso, pausar a shadow inmediatamente._"
        )
    else:
        actually_blocked_why = (
            "_Por qué: sin call-sites detectados aún, este criterio es preventivo._"
        )
        fp_why = (
            "_Por qué: cualquier FP en sample es un bloqueo real — no shadow._"
        )

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
        f"📊 **Qué mides:**\n\n"
        f"- `actually_blocked` — cuántas bloqueó el supervisor de verdad.\n"
        f"   {actually_blocked_why}\n\n"
        f"- `estimated_false_positive_rate` — target < 5%.\n"
        f"   {fp_why}\n\n"
        f"- Si aparecen falsos positivos → volver a shadow "
        f"(`SUPERVISOR_ENFORCEMENT_MODE=shadow`) y ajustar la policy antes de reintentar.\n\n"
        f"✅ **Cuándo avanzas a enforce completo:**\n\n"
        f"{_render_criteria(criteria)}\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _phase_enforce(n: int, active: list[Tier], findings: list[Finding]) -> str:
    progression = " → ".join(TIER_COPY[t]["title"] for t in active)
    rollback = _enforce_rollback_criterion(active, findings)
    buckets = group_by_risk_tier(findings)

    # Latency rationale — count across all active tiers (that's the critical path).
    total_active = sum(len(buckets[t]) for t in active)
    latency_why = _why_latency_targets(active[0] if active else "general",
                                       [f for t in active for f in buckets[t]])

    # actually_blocked per-tier rationale
    if total_active > 0:
        ab_why = (
            f"_Por qué: sobre {_possessive_count(total_active, 'call-site activo', 'call-sites activos')}, el "
            f"número de bloqueos reales te dice si la policy cubre lo que "
            f"importa. Cero bloqueos durante 48h con tráfico = guard "
            f"desconectado o policy inerte._"
        )
        fp_why_enforce = (
            f"_Por qué: por tier, {_fp_tolerance(total_active)} es la "
            f"tolerancia antes de rollback. Sostenido arriba de 5% significa "
            f"que la policy está generando fricción para users legítimos._"
        )
    else:
        ab_why = "_Por qué: sin findings, mide que el guard esté respondiendo._"
        fp_why_enforce = "_Por qué: umbral genérico de confianza._"

    return (
        f"## Fase {n} — Enforce progresivo\n\n"
        f"🎯 **Qué es esta fase:**\n"
        f"El supervisor bloquea por policy en los tiers activos. Progresión "
        f"sugerida (mayor severidad primero): **{progression}**.\n\n"
        f"🔧 **Qué haces:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=enforce` en el env.\n"
        f"2. Para el tier actual en la progresión, cambiar sus stubs a "
        f"`on_review=\"block\"` (poll por decisión de revisor humano). Los demás "
        f"tiers mantienen `on_review=\"shadow\"` hasta llegarles el turno.\n"
        f"3. Esperar a que el tier actual mantenga FP rate < 5% antes de pasar al siguiente.\n\n"
        f"📊 **Qué mides:**\n\n"
        f"- `actually_blocked` por tier — estable durante 48h antes de pasar al siguiente.\n"
        f"   {ab_why}\n\n"
        f"- `estimated_false_positive_rate` por tier — target < 5%.\n"
        f"   {fp_why_enforce}\n\n"
        f"- `latency_ms.p95 / p99` — target p95 < 200ms, p99 < 500ms.\n"
        f"   _Por qué: {latency_why}_\n\n"
        f"✅ **Rollback si algo sale mal:**\n\n"
        f"{_render_criteria([rollback])}\n"
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
        _phase_shadow(1, active, stack, findings),
    ]

    phase_n = 2
    if pacing == "large":
        blocks.append(_phase_sample(phase_n, primary, findings))
        phase_n += 1

    blocks.append(_phase_enforce(phase_n, active, findings))
    blocks.append(_metrics_block())
    blocks.append(_rollback_block())

    return "\n".join(blocks)
