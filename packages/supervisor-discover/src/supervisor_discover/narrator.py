"""Emit a mandable security-review message — runtime-supervisor/SUMMARY.md.

`report.md` is a technical document. `ROLLOUT.md` is a deploy playbook. Neither
is the thing you'd paste into a PR comment or email to the team. SUMMARY.md
is that thing: the repo owner reads it and knows exactly what to do, in order.

Priorization (the whole value of this file):
  🎯  Wrap points     — 1 decoration covers the agent; do this first
  🔒  High in prod    — high-confidence findings on non-test, non-install paths
  ⚠️  Confirm         — medium findings or high findings on install/setup paths
  🗑️  Discardable     — test fixtures, CI scripts, tutorial code

Also emits "Lo que NO me preocupa" so the reader sees what was checked and
ruled out — without that, they don't know if 0-findings in a tier means
"nothing there" or "scanner didn't look".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .classifier import group_by_risk_tier
from .combos import Combo
from .findings import Finding
from .summary import RepoSummary

Priority = Literal["wrap", "prod", "confirm", "discard"]

# Path fragments that mean "this file runs at install/build time, not on
# every agent decision". A subprocess.run in setup.py is not the same risk
# as a subprocess.run in the request handler.
_INSTALL_PATH_HINTS = (
    "/setup.py", "/setup_", "/install", "/migrate", "/bootstrap",
    "/scripts/", "/.github/", "/dockerfile",
)

# Path fragments that mean "this never runs in prod". Findings here are
# almost always noise from the repo owner's perspective.
_TEST_PATH_HINTS = (
    "/test_", "/tests/", "_test.py", "_test.ts", "_test.tsx",
    "/spec/", ".spec.ts", ".spec.tsx", "/__tests__/",
    "/fixtures/", "/mocks/", "/.fixtures/",
)


def _classify_path(file: str) -> Literal["prod", "install", "test"]:
    lower = file.lower()
    if any(h in lower for h in _TEST_PATH_HINTS):
        return "test"
    if any(h in lower for h in _INSTALL_PATH_HINTS):
        return "install"
    return "prod"


def _short_path(file: str) -> str:
    """Last two segments, so `a/b/c/d.py` → `c/d.py` — enough to locate."""
    parts = file.rsplit("/", 2)
    return "/".join(parts[-2:]) if len(parts) > 1 else file


@dataclass(frozen=True)
class PriorityItem:
    priority: Priority
    label: str              # short human title
    detail: str             # one-line explanation
    evidence: list[str]     # file:line references
    minutes_to_apply: int   # rough effort estimate


def _bucket_findings(findings: list[Finding]) -> dict[Priority, list[Finding]]:
    """Group findings into the 4 priority buckets based on confidence + path."""
    buckets: dict[Priority, list[Finding]] = {
        "wrap": [], "prod": [], "confirm": [], "discard": [],
    }
    for f in findings:
        # Agent orchestrator findings have their own routing: class defs and
        # tool registrations are wrap points (what the user should decorate);
        # framework imports are signal only; method defs in orchestrator paths
        # are ALSO wrap points (often `async execute()` / `handle()` — the
        # chokepoint itself, even when the scanner only gives medium confidence).
        if f.scanner == "agent-orchestrators":
            kind = f.extra.get("kind", "")
            path_kind = _classify_path(f.file)
            if path_kind == "test":
                buckets["discard"].append(f)
                continue
            if kind == "framework-import":
                # Imports are signal, not action — surface in narrative prose,
                # not as a priority item. Skip here.
                continue
            if kind in ("agent-class", "tool-registration", "agent-method"):
                buckets["wrap"].append(f)
                continue

        # HTTP routes are informational (tier=general). They describe the
        # traffic surface, but the supervisor doesn't gate the route itself —
        # it gates the tools INSIDE the route handler. Skip from priority
        # list; they're already in `report.md`'s General section.
        if f.scanner == "http-routes":
            continue

        path_kind = _classify_path(f.file)
        if path_kind == "test":
            buckets["discard"].append(f)
        elif path_kind == "install":
            buckets["confirm"].append(f)
        elif f.confidence == "high":
            buckets["prod"].append(f)
        else:  # prod-path, medium/low confidence
            buckets["confirm"].append(f)
    return buckets


def _group_by_scanner(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group findings by scanner, ordered by group size descending."""
    by_scanner: dict[str, list[Finding]] = {}
    for f in findings:
        by_scanner.setdefault(f.scanner, []).append(f)
    return sorted(by_scanner.items(), key=lambda kv: -len(kv[1]))


# Scanner → one-line capability label used in PriorityItem.label.
_SCANNER_LABEL: dict[str, str] = {
    "payment-calls": "payment SDK calls",
    "llm-calls": "LLM calls",
    "db-mutations": "DB mutations",
    "http-routes": "HTTP routes",
    "cron-schedules": "scheduled jobs",
    "voice-actions": "voice / telephony",
    "messaging": "messaging (slack / discord / sms)",
    "email-sends": "email sends",
    "calendar-actions": "calendar events",
    "fs-shell": "filesystem / shell exec",
    "media-gen": "generative media",
    "agent-orchestrators": "agent orchestration",
}


def _minutes_for(scanner: str, count: int) -> int:
    """Rough effort estimate: how long it takes to wrap N call-sites of one
    kind. Values come from actual walkthroughs — wrapping smtplib takes
    ~5 min per site, shell-exec needs judgment so bump it up. These are
    guidance for the reader, not a commitment."""
    per_site = {
        "email-sends": 5, "messaging": 5, "calendar-actions": 5,
        "payment-calls": 8, "voice-actions": 8, "media-gen": 8,
        "fs-shell": 10, "llm-calls": 5, "db-mutations": 8,
        "http-routes": 5, "cron-schedules": 3,
    }
    return max(5, per_site.get(scanner, 5) * count)


def _wrap_item(f: Finding) -> PriorityItem:
    kind = f.extra.get("kind", "")
    label = (
        f.extra.get("class_name")
        or f.extra.get("tool_name")
        or f.extra.get("method_name")
        or f.extra.get("framework")
        or "agent"
    )
    if kind == "agent-class":
        detail = f"wrap `{label}` → 1 decoration cubre todos los tools del agente (actuales y futuros)"
    elif kind == "agent-method":
        detail = f"método `{label}()` en path de orquestador → chokepoint, 1 wrap cubre todos los tools"
    else:  # tool-registration
        detail = f"tool registration `{label}` → policy por-tool sin tocar código del agente"
    return PriorityItem(
        priority="wrap",
        label=f"Wrap `{label}`",
        detail=detail,
        evidence=[f"{_short_path(f.file)}:{f.line}"],
        minutes_to_apply=10,
    )


def _group_item(
    priority: Priority,
    scanner: str,
    findings: list[Finding],
) -> PriorityItem:
    capability = _SCANNER_LABEL.get(scanner, scanner)
    count = len(findings)
    evidence = [f"{_short_path(f.file)}:{f.line}" for f in findings[:3]]
    if count > 3:
        evidence.append(f"+{count - 3} más")

    if priority == "prod":
        label = f"Gate {count} {capability} call-site(s)"
        detail = f"high-confidence, prod paths → `@supervised('{findings[0].suggested_action_type}')`"
    elif priority == "confirm":
        label = f"Confirma {count} {capability} call-site(s)"
        detail = "install/setup path o medium confidence → ¿corren en prod o solo build-time?"
    else:  # discard
        label = f"{count} {capability} en tests"
        detail = "test fixtures → ignorables salvo que apunten a tu DB de prod"

    return PriorityItem(
        priority=priority,
        label=label,
        detail=detail,
        evidence=evidence,
        minutes_to_apply=_minutes_for(scanner, count),
    )


def _build_priority_list(findings: list[Finding]) -> list[PriorityItem]:
    buckets = _bucket_findings(findings)
    items: list[PriorityItem] = []

    # 🎯 Wrap — one item per chokepoint. Order: classes first (strongest
    # signal), then methods (same file often — collapse to 1 item per file),
    # then tool registrations.
    wraps = buckets["wrap"]
    class_wraps = [f for f in wraps if f.extra.get("kind") == "agent-class"]
    method_wraps = [f for f in wraps if f.extra.get("kind") == "agent-method"]
    reg_wraps = [f for f in wraps if f.extra.get("kind") == "tool-registration"]

    for f in class_wraps[:3]:
        items.append(_wrap_item(f))

    # Collapse method findings by file — often the same `execute()` method
    # gets flagged multiple lines in one file; show it once with all lines
    # as evidence.
    by_file: dict[str, list[Finding]] = {}
    for f in method_wraps:
        by_file.setdefault(f.file, []).append(f)
    for file, fs in list(by_file.items())[:3]:
        primary = fs[0]
        method_name = primary.extra.get("method_name") or "execute"
        lines = sorted({ff.line for ff in fs})
        evidence = [f"{_short_path(file)}:{ln}" for ln in lines[:3]]
        if len(lines) > 3:
            evidence.append(f"+{len(lines) - 3} más")
        items.append(PriorityItem(
            priority="wrap",
            label=f"Wrap `{method_name}()` en `{_short_path(file)}`",
            detail="chokepoint del orquestador — 1 wrap cubre todos los tools que pase por aquí",
            evidence=evidence,
            minutes_to_apply=15,
        ))

    # Tool registrations are usually many — collapse to one item if there are
    # several of the same scanner, one per unique tool name if few.
    if reg_wraps:
        unique_tools = sorted({f.extra.get("tool_name") for f in reg_wraps if f.extra.get("tool_name")})
        if len(unique_tools) > 3:
            items.append(PriorityItem(
                priority="wrap",
                label=f"Policies por-tool ({len(unique_tools)} tools)",
                detail=f"tools expuestos: {', '.join(str(t) for t in unique_tools[:5])}{'...' if len(unique_tools) > 5 else ''}",
                evidence=[f"{_short_path(f.file)}:{f.line}" for f in reg_wraps[:3]],
                minutes_to_apply=max(15, 3 * len(unique_tools)),
            ))
        else:
            for f in reg_wraps:
                items.append(_wrap_item(f))

    # 🔒 Prod — group by scanner, largest first
    for scanner, fs in _group_by_scanner(buckets["prod"]):
        items.append(_group_item("prod", scanner, fs))

    # ⚠️ Confirm — same pattern
    for scanner, fs in _group_by_scanner(buckets["confirm"]):
        items.append(_group_item("confirm", scanner, fs))

    # 🗑️ Discard — collapse all test-path findings into one line regardless of scanner
    if buckets["discard"]:
        discard_findings = buckets["discard"]
        scanners_seen = sorted({f.scanner for f in discard_findings})
        evidence = [f"{_short_path(f.file)}:{f.line}" for f in discard_findings[:3]]
        if len(discard_findings) > 3:
            evidence.append(f"+{len(discard_findings) - 3} más")
        items.append(PriorityItem(
            priority="discard",
            label=f"{len(discard_findings)} findings en tests/fixtures",
            detail=f"scanners: {', '.join(scanners_seen)} — paths de test, no corren en prod",
            evidence=evidence,
            minutes_to_apply=0,
        ))

    return items


# ── "No me preocupa" ─────────────────────────────────────────────────

def _clean_tiers_notes(findings: list[Finding], summary: RepoSummary) -> list[str]:
    """Human-readable bullets for tiers where the scanner looked and found
    nothing. Important to say explicitly — "0 findings" without context
    reads as "the scanner might be broken"."""
    buckets = group_by_risk_tier(findings)
    notes: list[str] = []

    # Money
    money_items = buckets["money"]
    if not money_items and not summary.payment_integrations:
        notes.append("Sin SDKs de pago (stripe / paypal / plaid / adyen) — el agente no mueve dinero directo.")

    # Customer data
    cd_items = buckets["customer_data"]
    if not cd_items and not summary.sensitive_tables:
        notes.append("Sin mutaciones directas a tablas de clientes (UPDATE/DELETE users/customers/orders).")

    # LLM (when there's no explicit LLM SDK AND no agent-orchestrator)
    llm_items = buckets["llm"]
    has_agent = bool(summary.agent_chokepoints or summary.agent_tools)
    if not llm_items and not summary.llm_providers and not has_agent:
        notes.append("Sin LLM SDKs directos (anthropic / openai / langchain).")

    return notes


# ── timeline ─────────────────────────────────────────────────────────

def _timeline_block(items: list[PriorityItem], has_combos: bool) -> str:
    wrap_mins = sum(i.minutes_to_apply for i in items if i.priority == "wrap")
    prod_mins = sum(i.minutes_to_apply for i in items if i.priority == "prod")

    lines: list[str] = []
    if wrap_mins:
        lines.append(f"- **Hoy ({wrap_mins} min):** aplicar los wrap points 🎯. Deploy en shadow.")
    elif prod_mins:
        est_hours = max(1, round(prod_mins / 60))
        lines.append(f"- **Hoy (~{est_hours}h):** wrappear las call-sites 🔒. Deploy en shadow.")
    else:
        lines.append("- **Hoy:** nada crítico detectado. Instalar el supervisor en shadow igual para futuros cambios.")

    lines.append("- **2–3 días:** acumular observaciones. Revisar `would_block_in_shadow` en el dashboard. Ajustar policies si hay FPs.")
    lines.append("- **Día 4+:** flip a `SUPERVISOR_ENFORCEMENT_MODE=enforce` cuando FP rate < 5%.")
    if has_combos:
        lines.append("- **Combos:** ver `runtime-supervisor/combos/` — cada uno tiene el código copy-paste.")
    return "\n".join(lines)


# ── main render ──────────────────────────────────────────────────────

def _emoji(p: Priority) -> str:
    return {"wrap": "🎯", "prod": "🔒", "confirm": "⚠️", "discard": "🗑️"}[p]


def _render_item(item: PriorityItem) -> str:
    ev = " · ".join(f"`{e}`" for e in item.evidence) if item.evidence else ""
    mins = f"  _(~{item.minutes_to_apply} min)_" if item.minutes_to_apply > 0 else ""
    lines = [
        f"{_emoji(item.priority)}  **{item.label}**{mins}",
        f"    {item.detail}",
    ]
    if ev:
        lines.append(f"    {ev}")
    return "\n".join(lines)


def render_summary(
    summary: RepoSummary,
    findings: list[Finding],
    combos: list[Combo] | None = None,
    repo_name: str | None = None,
) -> str:
    """Build the SUMMARY.md content — a mandable security review."""
    combos = combos or []
    items = _build_priority_list(findings)
    clean_notes = _clean_tiers_notes(findings, summary)

    intro: list[str]
    if not findings:
        intro = [
            "Escaneé el repo y no encontré call-sites que necesiten supervisión hoy.",
            "Instalá el supervisor en shadow de todos modos — el próximo scan "
            "detectará integraciones nuevas automáticamente.",
        ]
    else:
        # All action items the reader should act on (wrap + prod + confirm).
        # "Discard" isn't an action — it's noise removed. Wraps count 1 each.
        priority_count = sum(1 for i in items if i.priority in ("wrap", "prod", "confirm"))
        if priority_count == 0:
            intro = [
                f"Escaneé {summary.one_liner}.",
                "Nada crítico en prod. Los findings son install-time o test fixtures "
                "— revisá la lista para confirmar que no hay falsos negativos.",
            ]
        else:
            intro = [
                f"Escaneé {summary.one_liner}.",
                f"**{priority_count} acciones** en orden de prioridad — "
                "empezá arriba, cada una es independiente.",
            ]

    title_bits = []
    if repo_name:
        title_bits.append(f"`{repo_name}`")
    title_bits.append("security review")
    lines: list[str] = [
        f"# {' — '.join(title_bits)}",
        "",
        *intro,
        "",
    ]

    # Priority list
    if items:
        for item in items:
            lines.append(_render_item(item))
            lines.append("")

    # Lo que NO me preocupa
    if clean_notes:
        lines.append("## Lo que NO me preocupa")
        lines.append("")
        for note in clean_notes:
            lines.append(f"- {note}")
        lines.append("")

    # Combos pointer
    if combos:
        lines.append("## Combos detectados")
        lines.append("")
        lines.append(
            f"Detecté {len(combos)} combinación(es) peligrosas — cada una tiene un "
            "playbook específico con código copy-paste:"
        )
        lines.append("")
        for c in combos:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(c.severity, "•")
            lines.append(f"- {emoji} **{c.title}** — `runtime-supervisor/combos/{c.id}.md`")
        lines.append("")

    # Timeline
    lines.append("## Timeline sugerido")
    lines.append("")
    lines.append(_timeline_block(items, bool(combos)))
    lines.append("")

    # Pointers
    lines.append("---")
    lines.append("")
    lines.append(
        "**Referencias:** detalle técnico en `report.md`; rollout por fases en "
        "`ROLLOUT.md`; stubs copy-paste en `stubs/`."
    )
    lines.append("")

    return "\n".join(lines)
