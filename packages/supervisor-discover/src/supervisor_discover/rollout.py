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
    "business_data": 30,  # trades/positions/inventory — mid-volume, mid-sensitivity
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
        "`configure()` with no arguments reads `SUPERVISOR_ENFORCEMENT_MODE` from "
        "the environment and defaults to shadow. To switch modes "
        "(shadow/sample/enforce) at runtime, change the env var and restart — "
        "no code redeploy needed."
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
    lines: list[str] = ["## Surface detected", ""]

    stack_label = {
        "python": "Python",
        "typescript": "TypeScript/JavaScript",
        "mixed": "Python + TypeScript",
        "unknown": "framework not identified",
    }[stack]
    fw_str = ", ".join(summary.frameworks) if summary.frameworks else "—"
    lines.append(f"- **Stack:** {stack_label} ({fw_str})")

    if summary.payment_integrations:
        parts = []
        for vendor, caps in summary.payment_integrations.items():
            parts.append(f"{vendor.capitalize()} ({', '.join(caps)})" if caps else vendor.capitalize())
        lines.append(f"- **Payments:** {', '.join(parts)}")

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
        lines.append("- **Call-sites to gate:**")
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
            f"the scanner didn't find any call-sites in this tier, so the "
            f"minimum threshold of {floor} observations only applies if new "
            f"call-sites appear in future scans."
        )
    noun = _pluralize(count, "call-site", "call-sites")
    if count < floor:
        return (
            f"your repo has {noun} of {title} — small static surface. The "
            f"floor is {floor} **runtime observations** (not call-sites) "
            f"because each call-site can fire with many different argument "
            f"patterns. You need to see the runtime variety, not just the "
            f"happy path."
        )
    return (
        f"your repo has {noun} of {title}. Below {floor} runtime "
        f"observations, the supervisor sees only a happy-path sample — you "
        f"can't tell a legit rare call-site from a real positive. On high-"
        f"traffic repos you clear this criterion in hours."
    )


def _why_fp_threshold(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    title = TIER_COPY[tier]["title"].lower()
    if count == 0:
        return (
            "while there are no observations, this criterion is trivial. It "
            "kicks in once real traffic arrives — more than 1 in 20 wrongly "
            "blocked calls erodes trust in the supervisor."
        )
    tolerance = _fp_tolerance(count)
    possessive = _possessive_count(count, "call-site", "call-sites")
    return (
        f"over {possessive} of {title}, 5% = {tolerance} per pass of the "
        f"policy engine. More than that and the supervisor feels like "
        f"friction, not protection — the team stops trusting it and looks "
        f"for ways to turn it off."
    )


def _why_no_legitimate_blocks(tier: Tier, items: list[Finding]) -> str:
    title = TIER_COPY[tier]["title"].lower()
    if not items:
        return (
            "with no call-sites detected, this criterion is preventive. It "
            "applies once the first high/medium finding appears in this tier."
        )
    top = _top_evidence_for_tier(items, limit=2)
    top_str = " · ".join(top)
    more = f" + {len(items) - len(top)} more" if len(items) > len(top) else ""
    # Singular vs plural intro
    if len(top) == 1 and not more:
        intro = f"the {title} call-site in your repo is {top_str}"
    else:
        intro = f"the top {title} call-sites in your repo are {top_str}{more}"
    return (
        f"{intro}. "
        f"If any of them shows up as \"would have blocked\" in shadow, "
        f"flipping to enforce breaks that flow in prod. Fix it first by "
        f"editing the YAML in `policies/` or by excluding the call-site "
        f"with `skip_policies`."
    )


def _why_actually_blocked(tier: Tier, items: list[Finding]) -> str:
    title = TIER_COPY[tier]["title"].lower()
    providers = _tier_providers(items)
    if providers:
        providers_str = ", ".join(f"`{p}`" for p in providers[:3])
        tail = f" (on your detected providers: {providers_str})"
    else:
        tail = ""
    return (
        f"if sample never blocked anything, the guard isn't wired up{tail}, "
        f"or no traffic matches the policy. Either way, flipping {title} to "
        f"enforce is blind — you don't know what happens next."
    )


def _why_fp_in_sample(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    title = TIER_COPY[tier]["title"].lower()
    if count == 0:
        return (
            "even with no call-sites detected, the policy could match future "
            "traffic — keeping the threshold prevents over-enforcing when it "
            "shows up."
        )
    return (
        f"when sampling 10% of {title}, any FP is visible in real production "
        f"(not shadow). Over {_possessive_count(count, 'detected call-site', 'detected call-sites')}, a sustained FP "
        f"rate > 5% means some legit flow is being blocked and nobody on the "
        f"team knows why. Pause and tune."
    )


def _why_sample_call_count(tier: Tier, items: list[Finding]) -> str:
    floor = _MIN_CALLS_BY_TIER[tier]
    title = TIER_COPY[tier]["title"].lower()
    return (
        f"≥ {floor} sampled calls gives you statistical coverage at 10% over "
        f"{title}. Less than that and the full enforce flip is a bet — you "
        f"don't have evidence the policy holds under real throughput."
    )


def _why_latency_targets(tier: Tier, items: list[Finding]) -> str:
    count = len(items)
    if count == 0:
        tail = ""
    else:
        tail = (
            f" Over {_possessive_count(count, 'call-site in this tier', 'call-sites in this tier')}, p99 > 500ms "
            f"shows up as a timeout in any interactive flow."
        )
    return (
        "the supervisor runs on the critical path. p95 > 200ms means the "
        "slowest 5% of calls add user-visible latency; users perceive the "
        f"supervisor as \"slowness\", not protection.{tail}"
    )


def _exit_criteria(tier: Tier, findings: list[Finding]) -> list[Criterion]:
    """Per-tier exit criteria for the Shadow phase — each rule paired with
    a repo-derived 'why'. Takes findings (not just tier) so the rationale
    can reference real counts, top providers, and evidence file:line."""
    floor = _MIN_CALLS_BY_TIER[tier]
    tier_items = group_by_risk_tier(findings)[tier]
    return [
        Criterion(
            rule=f"≥ {floor} runtime calls observed",
            why=_why_volume_floor(tier, tier_items),
        ),
        Criterion(
            rule="`estimated_false_positive_rate` < 5%",
            why=_why_fp_threshold(tier, tier_items),
        ),
        Criterion(
            rule="`would_block_in_shadow` contains no legitimate paths",
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
        tail = f" Active tiers in your repo: {tier_labels}."
    return Criterion(
        rule=(
            "If any enforced tier's FP rate > 5% → roll that tier back to "
            "`shadow`, tune the policy, and restart from Phase 1 or 2 for "
            "that specific tier."
        ),
        why=(
            "rollback is **per tier**, not global — the other enforced tiers "
            "keep protecting. That lets you fix a miscalibrated policy "
            "without losing coverage across the rest of the supervisor."
            f"{tail}"
        ),
    )


def _render_criteria(criteria: list[Criterion], *, indent: str = "") -> str:
    """Render a list of Criterion as markdown checkbox + italic rationale."""
    out: list[str] = []
    for c in criteria:
        out.append(f"{indent}- [ ] {c.rule}")
        out.append(f"{indent}   _Why: {c.why}_")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _metrics_block() -> str:
    """Short pointer block — the tier-specific metrics live inside each phase
    now. This just tells the reader where to look."""
    return (
        "## Where to watch metrics\n\n"
        "- **Local dashboard:** `http://localhost:3099/dashboard` if you installed "
        "with `ac start`. Recent entries, decisions per tier, review queue. "
        "Refreshes every 5s.\n"
        "- **Programmatic API:** `GET ${SUPERVISOR_BASE_URL}/v1/metrics/enforcement?window=24h` "
        "for CI, external dashboards, or when you need the data as JSON.\n\n"
        "Every phase above defines which metrics to watch at that specific "
        "moment — check the 📊 in the active phase.\n"
    )


def _rollback_block() -> str:
    return (
        "## Rollback\n\n"
        "Escape hatch, no redeploy needed:\n\n"
        "```bash\n"
        "export SUPERVISOR_ENFORCEMENT_MODE=shadow\n"
        "# restart the process; guards go back to observe-only\n"
        "```\n\n"
        "If the issue is the guard itself (network errors, supervisor latency), "
        "set `SUPERVISOR_ENFORCEMENT_MODE=off` and guards bypass entirely. "
        "Code keeps compiling and tests keep passing — it just stops evaluating.\n"
    )


_CRITERIA_GATED_NOTE = (
    "A phase ends when the exit criteria are met — not on a calendar week. "
    "A low-traffic repo may take longer to accumulate the minimum volume; a "
    "high-traffic one advances in days."
)


def _phase_shadow(
    n: int, active: list[Tier], stack: Stack, findings: list[Finding]
) -> str:
    tiers_label = (
        ", ".join(TIER_COPY[t]["title"].lower() for t in active)
        or "every relevant call-site"
    )
    # Exit criteria grouped by tier — each with its repo-derived "why".
    exit_blocks: list[str] = []
    for t in active:
        title = TIER_COPY[t]["title"]
        criteria = _exit_criteria(t, findings)
        exit_blocks.append(
            f"**{title}** — all {len(criteria)} criteria must pass:\n\n"
            + _render_criteria(criteria)
        )
    exit_section = "\n".join(exit_blocks) if exit_blocks else (
        "No active tiers — re-scan once you add critical call-sites.\n"
    )

    # Metrics bullets — each with repo-derived rationale.
    metric_lines = _render_shadow_metrics(active, findings)

    return (
        f"## Phase {n} — Shadow\n\n"
        f"🎯 **What this phase does:**\n"
        f"The supervisor watches every call and logs what it WOULD have done, "
        f"without blocking anything. Safe to deploy on day 1.\n\n"
        f"🔧 **What you do:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=shadow` in the env.\n"
        f"2. Bootstrap at startup:\n\n"
        f"{_shadow_config_block(stack)}\n\n"
        f"3. Paste the stubs from `stubs/` into your code — they cover {tiers_label}.\n"
        f"4. Normal deploy. Nothing blocks.\n\n"
        f"📊 **What you watch:**\n\n"
        f"{metric_lines}\n"
        f"✅ **When to advance to the next phase:**\n\n"
        f"{exit_section}\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _render_shadow_metrics(active: list[Tier], findings: list[Finding]) -> str:
    """Compose the '📊 What you watch' bullets for shadow phase. Each bullet
    gets a repo-derived 'why' inline so the reader knows why that
    metric matters for THEIR findings."""
    # Total items across active tiers — used to frame the FP-rate context.
    buckets = group_by_risk_tier(findings)
    total_active = sum(len(buckets[t]) for t in active)
    out: list[str] = []

    out.append(
        "- `would_block_in_shadow` — how many calls would have been blocked "
        "(target: no legitimate paths in the list)."
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
                f"   _Why: lets you build allowlists with real data — if "
                f"{all_top[0]} shows up as 'would have blocked' but it's a "
                f"normal flow, you tune the policy before it affects prod._"
            )
        else:
            out.append(
                "   _Why: lets you build allowlists with real data before "
                "you enforce._"
            )
    out.append("")

    out.append("- `estimated_false_positive_rate` — target < 5%.")
    if total_active > 0:
        out.append(
            f"   _Why: over {_possessive_count(total_active, 'active call-site', 'active call-sites')} "
            f"(high + medium), {_fp_tolerance(total_active)} per pass. "
            f"Above that the team perceives the supervisor as noise._"
        )
    else:
        out.append(
            "   _Why: more than 1 in 20 wrongly blocked calls erodes the "
            "team's trust in the supervisor._"
        )
    out.append("")

    out.append(
        "- If `would_block_in_shadow` includes legitimate paths → tune the "
        "YAML in `policies/` or exclude that call-site from the policy."
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
            f"_Why: of {_possessive_count(primary_count, 'call-site', 'call-sites')} in {title}, the 10% "
            f"sample should at least hit the high-confidence ones "
            f"({sum(1 for f in primary_items if f.confidence == 'high')} in your repo). "
            f"If `actually_blocked = 0` after days of traffic, either the guard "
            f"isn't installed or the policy matches nothing real._"
        )
        fp_why = (
            f"_Why: blocks are now real — not shadow. Over your "
            f"{primary_count} call-sites, {_fp_tolerance(primary_count)}. "
            f"Above that, roll back to shadow immediately._"
        )
    else:
        actually_blocked_why = (
            "_Why: with no call-sites detected yet, this criterion is preventive._"
        )
        fp_why = (
            "_Why: any FP during sample is a real block — not shadow._"
        )

    return (
        f"## Phase {n} — Sample 10% on {title}\n\n"
        f"🎯 **What this phase does:**\n"
        f"Enforces 10% of the calls in {title}; the other tiers stay in "
        f"shadow. First phase where the supervisor can block real traffic, "
        f"but narrowly.\n\n"
        f"🔧 **What you do:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=sample` + `SUPERVISOR_SAMPLE_PERCENT=10` in the env.\n"
        f"2. Restart the process — guards read the env at startup.\n"
        f"3. Leave the other tiers' stubs on `on_review=\"shadow\"` (don't touch them).\n\n"
        f"📊 **What you watch:**\n\n"
        f"- `actually_blocked` — how many blocks the supervisor actually fired.\n"
        f"   {actually_blocked_why}\n\n"
        f"- `estimated_false_positive_rate` — target < 5%.\n"
        f"   {fp_why}\n\n"
        f"- If false positives show up → roll back to shadow "
        f"(`SUPERVISOR_ENFORCEMENT_MODE=shadow`) and tune the policy before retrying.\n\n"
        f"✅ **When to advance to full enforce:**\n\n"
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
            f"_Why: over {_possessive_count(total_active, 'active call-site', 'active call-sites')}, the "
            f"number of real blocks tells you if the policy covers what "
            f"matters. Zero blocks for 48h with real traffic = guard "
            f"disconnected or dead policy._"
        )
        fp_why_enforce = (
            f"_Why: per tier, {_fp_tolerance(total_active)} is the "
            f"tolerance before rollback. Sustained above 5% means the "
            f"policy is creating friction for legitimate users._"
        )
    else:
        ab_why = "_Why: with no findings, this just confirms the guard is responding._"
        fp_why_enforce = "_Why: generic trust threshold._"

    return (
        f"## Phase {n} — Progressive enforce\n\n"
        f"🎯 **What this phase does:**\n"
        f"The supervisor blocks per policy on the active tiers. Suggested "
        f"progression (highest severity first): **{progression}**.\n\n"
        f"🔧 **What you do:**\n"
        f"1. `SUPERVISOR_ENFORCEMENT_MODE=enforce` in the env.\n"
        f"2. For the current tier in the progression, switch its stubs to "
        f"`on_review=\"block\"` (poll for the human reviewer's decision). The "
        f"other tiers stay on `on_review=\"shadow\"` until their turn.\n"
        f"3. Wait until the current tier holds FP rate < 5% before moving on.\n\n"
        f"📊 **What you watch:**\n\n"
        f"- `actually_blocked` per tier — steady for 48h before advancing.\n"
        f"   {ab_why}\n\n"
        f"- `estimated_false_positive_rate` per tier — target < 5%.\n"
        f"   {fp_why_enforce}\n\n"
        f"- `latency_ms.p95 / p99` — target p95 < 200ms, p99 < 500ms.\n"
        f"   _Why: {latency_why}_\n\n"
        f"✅ **Rollback if something breaks:**\n\n"
        f"{_render_criteria([rollback])}\n"
        f"_{_CRITERIA_GATED_NOTE}_\n"
    )


def _short_rollout(summary: RepoSummary, findings: list[Finding], stack: Stack) -> str:
    """For minimal repos — skip the multi-phase plan."""
    active = _active_tiers(findings)
    tiers_label = ", ".join(TIER_COPY[t]["title"].lower() for t in active) if active else "the informational call-sites"

    lines = [
        f"# Rollout playbook — {summary.one_liner}",
        "",
        "Small surface: no HIGH call-sites in any tier, so the rollout "
        "collapses to a single observation phase. Once HIGH findings show up "
        "(new integrations, added call-sites), re-scan and the extended "
        "playbook regenerates automatically.",
        "",
        _surface_block(summary, findings, stack),
        "## Single phase — indefinite Shadow",
        "",
        "Setup: `SUPERVISOR_ENFORCEMENT_MODE=shadow`. Bootstrap at startup:",
        "",
        _shadow_config_block(stack),
        "",
        "What to do:",
        f"1. Paste the stubs (they cover {tiers_label}).",
        "2. Normal deploy.",
        "3. Re-scan (`supervisor-discover scan`) when you add new integrations "
        "(payments, LLM providers, scheduled jobs). If HIGH call-sites show up, "
        "regenerate this ROLLOUT.md and follow the extended playbook.",
        "",
        _metrics_block(),
        _rollback_block(),
    ]
    return "\n".join(lines)


def _empty_rollout(summary: RepoSummary) -> str:
    return (
        f"# Rollout playbook — {summary.one_liner}\n\n"
        "The scan found no call-sites that justify a phased rollout.\n\n"
        "Re-scan when you:\n"
        "- Add a payment SDK (Stripe, Adyen, etc.)\n"
        "- Add an LLM provider (OpenAI, Anthropic, etc.)\n"
        "- Add direct mutations on sensitive tables (users/orders/customers/...)\n\n"
        "The supervisor has nothing to gate in this repo today. Leave it "
        "installed with `SUPERVISOR_ENFORCEMENT_MODE=shadow` so future "
        "changes show up in the next scan.\n"
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
        "This playbook walks you from *shadow* (observe, never block) to *enforce* "
        "(block per policy), measuring volume and false positives at every step.",
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
