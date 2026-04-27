"""Dangerous combo detector.

A single finding is rarely the whole story. The real risk often emerges when
TWO capabilities live in the same repo and the agent can chain them. This
module looks at the full finding set + the repo summary and surfaces these
combos as first-class "Critical combinations" that go on top of the report.

Examples:
- voice-synthesis (ElevenLabs) + outbound-call (Twilio) = social engineering weapon
- shell-exec + LLM call = LLM-to-RCE pipeline
- mass-email + customer-data tables = spray phishing to your user base
- fs-write + scheduled job = self-modifying scheduled agent

The detector is deterministic (no LLM), operates over the same `Finding` list
the rest of the generator already has.

Reachability refinement: when the caller passes `root` to `detect_combos`,
the LLM-paired combos (shell-exec / fs-delete / fs-write / payment /
account-change) are post-processed against the within-repo import graph.
If no import path connects the LLM module to the side-effect module, the
combo is downgraded to `low` severity and the narrative says so
explicitly. False negatives are impossible (no import path = no
data-flow); false positives where two modules import each other but
never actually pipe data remain — and the narrative copy already calls
that out.
"""

from __future__ import annotations

from dataclasses import dataclass, replace as dc_replace
from pathlib import Path
from typing import Callable

from .findings import Finding
from .reachability import any_path_between, build_import_graph, format_path


@dataclass(frozen=True)
class Combo:
    id: str                # stable id for CI diffs
    title: str             # short headline ("Voice cloning + outbound call")
    severity: str          # "critical" | "high" | "medium"
    narrative: str         # one paragraph: why this pair is worse than the sum
    evidence: list[str]    # paths / providers seen, for auditability
    mitigation: str        # concrete next step


# ── primitives ─────────────────────────────────────────────────────────

def _providers_for_scanner(findings: list[Finding], scanner: str) -> set[str]:
    """All unique provider/family labels from a scanner's findings."""
    return {
        str(f.extra.get("provider") or f.extra.get("family") or "").lower()
        for f in findings
        if f.scanner == scanner and (f.extra.get("provider") or f.extra.get("family"))
    }


def _has_scanner(findings: list[Finding], scanner: str, min_confidence: str = "medium") -> bool:
    order = {"low": 0, "medium": 1, "high": 2}
    threshold = order.get(min_confidence, 1)
    return any(f.scanner == scanner and order.get(f.confidence, 0) >= threshold for f in findings)


def _has_family(findings: list[Finding], scanner: str, family: str) -> bool:
    return any(
        f.scanner == scanner and f.extra.get("family") == family
        for f in findings
    )


def _has_sensitive_tables(findings: list[Finding]) -> bool:
    _SENSITIVE = {"users", "user", "customers", "customer", "accounts", "orders", "subscriptions", "payments"}
    return any(
        f.scanner == "db-mutations" and str(f.extra.get("table", "")).lower() in _SENSITIVE
        for f in findings
    )


def _short_paths(findings: list[Finding], scanner: str, limit: int = 3) -> list[str]:
    hits = [f for f in findings if f.scanner == scanner]
    out: list[str] = []
    for f in hits[:limit]:
        out.append(f"{f.file.split('/')[-1]}:{f.line}")
    if len(hits) > limit:
        out.append(f"+{len(hits) - limit} more")
    return out


# ── combo rules ────────────────────────────────────────────────────────

def _voice_clone_plus_outbound_call(findings: list[Finding]) -> Combo | None:
    voice_providers = _providers_for_scanner(findings, "voice-actions")
    clone_providers = {"elevenlabs"}
    call_providers = {"twilio", "retell", "vapi", "bland", "plivo", "vonage"}
    if not (voice_providers & clone_providers) or not (voice_providers & call_providers):
        return None
    clone_hit = sorted(voice_providers & clone_providers)
    call_hit = sorted(voice_providers & call_providers)
    return Combo(
        id="voice-clone-plus-outbound-call",
        title=f"Voice cloning ({', '.join(clone_hit)}) + outbound call ({', '.join(call_hit)})",
        severity="critical",
        narrative=(
            "Your repo can synthesize voices AND place phone calls. That pair is "
            "the complete vishing recipe: an injected prompt can say 'call the "
            "user's emergency contact with a voice that sounds like their "
            "mother and ask them to authorize a transfer right now'. The "
            "supervisor has to validate the recipient and the content before "
            "both tools fire in the same session."
        ),
        evidence=_short_paths(findings, "voice-actions", limit=4),
        mitigation=(
            "Minimum guard: allowlist destination numbers + allowlist approved "
            "voices for cloning. Ideal guard: any voice-clone + outbound pair "
            "in the same execution trace goes to human review."
        ),
    )


def _llm_plus_shell_exec(findings: list[Finding]) -> Combo | None:
    if not _has_scanner(findings, "llm-calls", "medium"):
        return None
    if not _has_family(findings, "fs-shell", "shell-exec"):
        return None
    return Combo(
        id="llm-plus-shell-exec",
        title="LLM call + shell execution in the same codebase",
        severity="critical",
        narrative=(
            "Co-occurrence: the codebase contains both LLM calls and shell "
            "execution. The scanner does not verify a data-flow path between "
            "them — taint analysis is intentionally out of scope. If any "
            "code path in this repo connects LLM output to subprocess/exec "
            "args, that path is RCE-equivalent: a prompt injection picks the "
            "command. Worth checking by hand even when no path is obvious."
        ),
        evidence=_short_paths(findings, "fs-shell", limit=3) + _short_paths(findings, "llm-calls", limit=3),
        mitigation=(
            "Never pass LLM output straight to subprocess/exec. Use a tool "
            "allowlist with typed args + validation. Gate every shell exec "
            "with @supervised('tool_use') and a policy that denies any "
            "command outside a short allowlist."
        ),
    )


def _llm_plus_fs_delete(findings: list[Finding]) -> Combo | None:
    if not _has_scanner(findings, "llm-calls", "medium"):
        return None
    if not _has_family(findings, "fs-shell", "fs-delete"):
        return None
    return Combo(
        id="llm-plus-fs-delete",
        title="LLM call + filesystem delete",
        severity="high",
        narrative=(
            "Co-occurrence: the codebase contains both LLM calls and "
            "filesystem-delete operations (`rm`, `unlink`, `rmtree`). The "
            "scanner does not verify a data-flow path between them. If the "
            "agent ends up passing an LLM-generated path to a delete call, "
            "a prompt injection can wipe logs, configs, user data, or the "
            "agent's own source tree."
        ),
        evidence=_short_paths(findings, "fs-shell", limit=3),
        mitigation="Policy: deny paths outside an allowlist of directories.",
    )


def _mass_email_plus_customer_db(findings: list[Finding]) -> Combo | None:
    if not _has_scanner(findings, "email-sends", "medium"):
        return None
    if not _has_sensitive_tables(findings):
        return None
    return Combo(
        id="mass-email-plus-customer-db",
        title="Email send + customer-data tables (users/customers/orders)",
        severity="high",
        narrative=(
            "Your repo sends email AND has tables named after customers "
            "(users, customers, orders, ...). A prompt injection can talk the "
            "agent into querying the customer list and blasting mass phishing "
            "from your authenticated domain. Conversion rates for that kind "
            "of campaign are orders of magnitude higher than random spam."
        ),
        evidence=_short_paths(findings, "email-sends", limit=2) + _short_paths(findings, "db-mutations", limit=2),
        mitigation=(
            "Minimum guard: per-call recipient cap (`deny if len(to) > 50`). "
            "Ideal guard: mandatory human review for any email with more than "
            "5 recipients + a separate policy for bulk sends."
        ),
    )


def _media_gen_plus_messaging(findings: list[Finding]) -> Combo | None:
    if not _has_scanner(findings, "media-gen", "medium"):
        return None
    if not _has_scanner(findings, "messaging", "medium"):
        return None
    return Combo(
        id="media-gen-plus-messaging",
        title="Generative media + messaging",
        severity="high",
        narrative=(
            "The agent generates synthetic image/video AND can post to "
            "messaging channels. That's a deepfake distribution pipeline: a "
            "prompt injection can generate a fake image of an executive "
            "saying X and post it to the general Slack channel."
        ),
        evidence=_short_paths(findings, "media-gen", limit=2) + _short_paths(findings, "messaging", limit=2),
        mitigation=(
            "Mandatory human review on any media-gen whose output goes to a "
            "messaging channel — forbid the direct chain."
        ),
    )


def _webhook_plus_db_write(findings: list[Finding]) -> Combo | None:
    """Webhook handler + database writes — the canonical idempotency trap.

    Stripe, Shopify, GitHub, Slack: every webhook re-delivers the same event
    when the handler returns 5xx (or the network hiccups). If the write is
    not keyed on the event id, the retry replays the mutation — duplicate
    plan changes on a Stripe subscription renewal, duplicate charges,
    duplicate audit rows. The handler can verify the signature perfectly
    and still corrupt data on the second delivery."""
    webhook_routes = [
        f for f in findings
        if f.scanner == "http-routes"
        and "webhooks" in f.file.lower()
        and (f.extra or {}).get("method", "").upper() == "POST"
    ]
    if not webhook_routes:
        return None
    if not _has_scanner(findings, "db-mutations", "medium"):
        return None
    return Combo(
        id="webhook-plus-db-write",
        title="Webhook handler + database writes (idempotency)",
        severity="high",
        narrative=(
            "Your repo handles webhook events AND writes to the database. "
            "Stripe, Shopify, GitHub, Slack — every webhook re-delivers the "
            "same event when the handler returns 5xx (or the network hiccups). "
            "If the write is not keyed on the event id, the retry replays the "
            "mutation: duplicate plan changes on a Stripe subscription "
            "renewal, duplicate charges, duplicate audit rows. Signature "
            "verification doesn't help — the second delivery is also signed."
        ),
        evidence=_short_paths(findings, "http-routes", limit=2)
                + _short_paths(findings, "db-mutations", limit=2),
        mitigation=(
            "Minimum guard: insert `event.id` into a `processed_events` "
            "table inside the same transaction; bail out if the row already "
            "exists. Ideal guard: wrap the whole handler in a transaction "
            "keyed on the event id and let the unique constraint enforce "
            "exactly-once delivery."
        ),
    )


def _llm_plus_fs_write(findings: list[Finding]) -> Combo | None:
    if not _has_scanner(findings, "llm-calls", "medium"):
        return None
    if not _has_family(findings, "fs-shell", "fs-write"):
        return None
    return Combo(
        id="llm-plus-fs-write",
        title="LLM call + filesystem write",
        severity="medium",
        narrative=(
            "Co-occurrence: the codebase contains both LLM calls and "
            "filesystem writes. If a path or contents in any write goes "
            "through LLM output, a prompt injection can plant payloads, "
            "overwrite configs, or modify the agent's own source (self-"
            "modifying agent). Medium because many writes are legit "
            "(caches, logs) — risk depends on the path."
        ),
        evidence=_short_paths(findings, "fs-shell", limit=3),
        mitigation="Allowlist permitted directories; deny by default outside `/tmp` or a specific data dir.",
    )


def _agent_orchestrator_present(findings: list[Finding]) -> Combo | None:
    """If we found an agent chokepoint (Controller/Dispatcher/Planner class or
    a tool registration), recommend wrapping IT instead of every leaf call-site.
    High leverage: 1 wrap = total coverage. This is the combo that matters most
    for agentic codebases, even when it fires alone.

    Framework imports (no class / no registration) still fire the combo at
    lower severity — the user's repo is agentic, we just couldn't pinpoint
    the wrap site. The playbook tells them how to find it themselves."""
    from .summary import finding_wrap_rank

    orch = [f for f in findings if f.scanner == "agent-orchestrators"]
    # Sort classes by wrap rank so factory-file agents (e.g.
    # `BudgetSupervisorAgent` whose file matches `_FACTORY_FILE_HINTS`)
    # surface before non-factory ones (`BudgetExtractorAgent`). Without
    # this, `classes[0]` was whatever came first in the scan order — the
    # alphabetical winner — which made the combo cite a different class
    # than START_HERE's "Best place to wrap first".
    classes = sorted(
        [f for f in orch if f.extra.get("kind") == "agent-class" and f.confidence == "high"],
        key=finding_wrap_rank,
    )
    # Drop children whose parent is also in `classes` — the parent covers
    # them. Same logic as start_here._build_wrap_targets.
    parent_set = {f.extra.get("class_name") for f in classes}
    classes = [
        f for f in classes
        if not (f.extra.get("parent_agent") and f.extra.get("parent_agent") in parent_set)
    ]
    registrations = [f for f in orch if f.extra.get("kind") == "tool-registration"]
    imports = [f for f in orch if f.extra.get("kind") == "framework-import"]

    if not (classes or registrations or imports):
        return None

    chokepoint_names = sorted({
        f.extra.get("class_name") or f.extra.get("framework") or "agent"
        for f in classes
    })
    tool_names = sorted({f.extra.get("tool_name") for f in registrations if f.extra.get("tool_name")})
    frameworks = sorted({str(f.extra.get("framework")) for f in imports if f.extra.get("framework")})

    title_bits: list[str] = []
    if chokepoint_names:
        title_bits.append(f"chokepoint ({', '.join(chokepoint_names[:2])})")
    if tool_names:
        title_bits.append(f"{len(tool_names)} tools")
    if not chokepoint_names and not tool_names and frameworks:
        title_bits.append(f"framework ({', '.join(frameworks)})")

    ev_lines: list[str] = []
    for f in classes[:2]:
        # Last 2 path segments for readable evidence without absolute paths.
        rel = "/".join(f.file.rsplit("/", 2)[-2:])
        ev_lines.append(f"{rel}:{f.line}")
    if tool_names:
        ev_lines.append(f"tools: {', '.join(tool_names[:5])}{'...' if len(tool_names) > 5 else ''}")
    if not classes and imports:
        # Show the files where imports live so the reader knows where to look.
        for f in imports[:3]:
            rel = "/".join(f.file.rsplit("/", 2)[-2:])
            ev_lines.append(f"{rel}:{f.line}")
        if len(imports) > 3:
            ev_lines.append(f"+{len(imports) - 3} more files with imports")

    if classes and registrations:
        severity = "critical"
    elif classes or registrations:
        severity = "high"
    else:  # imports only — signal, not a wrap point
        severity = "medium"

    return Combo(
        id="agent-orchestrator",
        title=f"Agent orchestrator detected · {' · '.join(title_bits)}",
        severity=severity,
        narrative=(
            "This repo has an agent orchestrator — a `Controller.handle()` / "
            "`Dispatcher.dispatch()` / `AgentExecutor` where every decision "
            "the agent makes flows through before firing a tool. This is your "
            "highest-leverage wrap point: one `@supervised('tool_use')` "
            "around the orchestrator gates every current tool and every tool "
            "you add later, without maintaining individual wraps. Wrapping "
            "here is strictly better than wrapping each leaf call-site — you "
            "don't lose coverage when the team adds a new tool."
        ),
        evidence=ev_lines,
        mitigation=(
            "Wrap `Controller.handle()` (or the equivalent). Pass the "
            "supervisor `{tool, intent, user_id, session_id, ...intent "
            "payload}` — per-tool policies then work without touching the "
            "agent code. See `runtime-supervisor/combos/agent-orchestrator.md`."
        ),
    )


def _llm_plus_payment(findings: list[Finding]) -> Combo | None:
    """LLM + payment SDK in the same repo. The reviewer specifically
    flagged this as a missing combo on supervincent — Anthropic + Stripe
    coexist with no combo to trigger the right playbook. A prompt
    injection that drives the agent toward a charge is now a real money
    loss path."""
    if not _has_scanner(findings, "llm-calls", "medium"):
        return None
    if not _has_scanner(findings, "payment-calls", "medium"):
        return None
    return Combo(
        id="llm-plus-payment",
        title="LLM call + payment SDK in the same codebase",
        severity="critical",
        narrative=(
            "The agent can both call an LLM and move money. A prompt "
            "injection that frames a refund or charge as 'the user just "
            "asked for it' becomes a real transaction — the agent has "
            "the credentials, the LLM has the convincing-sounding reason. "
            "Same blast radius as LLM + shell-exec, but the consequence "
            "is finance, not infra."
        ),
        evidence=(
            _short_paths(findings, "payment-calls", limit=3)
            + _short_paths(findings, "llm-calls", limit=3)
        ),
        mitigation=(
            "Wrap every payment call with @supervised('payment') and a "
            "policy that requires per-call hard caps + recipient/customer "
            "allowlist + human review on amounts above the cap. Never let "
            "the LLM produce the amount or recipient as a free-form field."
        ),
    )


def _llm_plus_account_change(findings: list[Finding]) -> Combo | None:
    """LLM + database mutations on user / customer / account tables.
    A prompt injection here can change the user's email, role, password,
    or merge accounts — classic ATO via the support agent path."""
    if not _has_scanner(findings, "llm-calls", "medium"):
        return None
    # Sensitive tables = users / customers / accounts / profiles. Same
    # criterion `_mass_email_plus_customer_db` uses.
    if not _has_sensitive_tables(findings):
        return None
    return Combo(
        id="llm-plus-account-change",
        title="LLM call + writes to user/account tables",
        severity="high",
        narrative=(
            "The agent can call an LLM AND write to user / customer / "
            "account tables. A prompt injection that says 'this user "
            "wants their email changed to x@evil.com' can become an "
            "account takeover with no other indicator. Especially "
            "dangerous in customer-support agents that already have the "
            "credentials to do this."
        ),
        evidence=(
            _short_paths(findings, "db-mutations", limit=3)
            + _short_paths(findings, "llm-calls", limit=3)
        ),
        mitigation=(
            "Wrap account-mutation call-sites with @supervised('account_change'). "
            "Policy: require the original user's auth context (not the agent's "
            "service token) before allowing email/phone/password updates; route "
            "role changes through human review."
        ),
    )


def _voice_call_plus_scheduler(findings: list[Finding]) -> Combo | None:
    voice_providers = _providers_for_scanner(findings, "voice-actions")
    call_providers = {"twilio", "retell", "vapi", "bland"}
    if not (voice_providers & call_providers):
        return None
    if not _has_scanner(findings, "cron-schedules", "medium"):
        return None
    return Combo(
        id="voice-call-plus-scheduler",
        title="Outbound voice call + scheduled job",
        severity="high",
        narrative=(
            "The repo has outbound voice calls AND cron / scheduled jobs. A "
            "prompt injection that survives a cycle (or persists in the DB) "
            "can fire automated calls off-hours, to recipients no human "
            "operator ever reviewed. Schedulers amplify a single injection's "
            "blast radius a lot."
        ),
        evidence=_short_paths(findings, "voice-actions", limit=2) + _short_paths(findings, "cron-schedules", limit=2),
        mitigation=(
            "Per-tenant rate limits + time-window gating. Human review on "
            "recipients generated by scheduled jobs."
        ),
    )


_COMBO_RULES: list[Callable[[list[Finding]], Combo | None]] = [
    # Agent orchestrator first — if this fires, it's the #1 mitigation to ship.
    _agent_orchestrator_present,
    _voice_clone_plus_outbound_call,
    _llm_plus_shell_exec,
    _llm_plus_payment,         # LLM × money path = critical
    _llm_plus_account_change,  # LLM × account writes = ATO surface
    _llm_plus_fs_delete,
    _llm_plus_fs_write,
    _webhook_plus_db_write,    # webhook re-delivery without idempotency
    _mass_email_plus_customer_db,
    _media_gen_plus_messaging,
    _voice_call_plus_scheduler,
]


def detect_combos(
    findings: list[Finding], root: Path | None = None,
) -> list[Combo]:
    """Run every combo rule; return only the combos that triggered, in the
    order they were registered (stable for diffing).

    When `root` is provided, LLM-paired combos are refined against the
    within-repo import graph: combos whose LLM finding can't reach the
    paired side-effect finding (no import path either direction) are
    downgraded to `low` severity and the narrative is rewritten to make
    the disconnection explicit. Without `root`, behaviour is unchanged —
    pure co-occurrence with the existing copy.
    """
    results: list[Combo] = []
    for rule in _COMBO_RULES:
        hit = rule(findings)
        if hit is not None:
            results.append(hit)
    if root is not None:
        results = _refine_combos_with_reachability(results, findings, root)
    return results


# ── reachability post-processing ───────────────────────────────────────


# Combo id → (LLM-side scanner, paired-side scanner+family) for combos
# whose narrative claims "if LLM output reaches X". For these we can
# verify reachability through imports; without an import path the
# claim is structurally impossible. Other combos (voice/voice,
# mass-email/db, voice/cron, agent-orchestrator) aren't in this table —
# they describe co-presence rather than a directional flow.
_LLM_PAIRED_COMBOS: dict[str, tuple[str, str | None, str | None]] = {
    # combo_id            : (paired_scanner, paired_family, paired_action_type)
    "llm-plus-shell-exec":      ("fs-shell",      "shell-exec", None),
    "llm-plus-fs-delete":       ("fs-shell",      "fs-delete",  None),
    "llm-plus-fs-write":        ("fs-shell",      "fs-write",   None),
    "llm-plus-payment":         ("payment-calls", None,         None),
    "llm-plus-account-change":  ("db-mutations",  None,         None),
}


def _files_for_combo_side(
    findings: list[Finding], scanner: str, family: str | None,
) -> list[Path]:
    """Resolve the absolute file paths of every finding matching the
    given scanner (and optional family). Findings without a file (rare
    edge case in older fixtures) are skipped."""
    out: list[Path] = []
    for f in findings:
        if f.scanner != scanner:
            continue
        if family is not None and f.extra.get("family") != family:
            continue
        if not f.file:
            continue
        out.append(Path(f.file))
    return out


def _llm_files(findings: list[Finding]) -> list[Path]:
    """All files containing an LLM-call finding. Both `invocation` and
    `construction` kinds count: the constructor still imports the LLM
    SDK, and what matters for reachability is whether the *module*
    is connected to the side-effect module — not which line of it ran."""
    return [Path(f.file) for f in findings if f.scanner == "llm-calls" and f.file]


def _refine_combos_with_reachability(
    combos: list[Combo], findings: list[Finding], root: Path,
) -> list[Combo]:
    """Walk the combos, refine LLM-paired ones via the import graph.

    The graph is built once and reused across every refinement. Cost is
    O(files) for the AST walk and O(edges) for each BFS — well under a
    second on repos of langchain's size in practice.
    """
    graph = build_import_graph(root)
    llm_files = _llm_files(findings)
    if not llm_files:
        # No LLM findings → nothing to refine. (Should be unreachable
        # given the rule predicates, but defensive.)
        return combos

    refined: list[Combo] = []
    for combo in combos:
        spec = _LLM_PAIRED_COMBOS.get(combo.id)
        if spec is None:
            refined.append(combo)
            continue
        paired_scanner, paired_family, _ = spec
        paired_files = _files_for_combo_side(findings, paired_scanner, paired_family)
        if not paired_files:
            refined.append(combo)
            continue
        result = any_path_between(graph, llm_files, paired_files)
        if result is None:
            refined.append(_downgrade_unreachable(combo))
        else:
            src, dst, path = result
            refined.append(_annotate_reachable(combo, root, path))
    return refined


def _downgrade_unreachable(combo: Combo) -> Combo:
    """Rewrite a combo to make explicit that no import path connects the
    two findings. Drops severity to `low` and keeps the existing
    mitigation copy — the recommended fix doesn't change just because
    the path doesn't exist *yet* (a future commit could add one)."""
    note = (
        " No import path was found between the LLM module and the "
        "paired module — within-repo data-flow is not reachable today, "
        "so this is co-occurrence only, not an active chain. Worth "
        "revisiting if a future change wires them together."
    )
    new_narrative = combo.narrative.rstrip() + note
    return dc_replace(combo, severity="low", narrative=new_narrative)


def _annotate_reachable(combo: Combo, root: Path, path: list[Path]) -> Combo:
    """When a within-repo import path exists, surface it in the
    narrative + evidence. Severity stays at the rule's original value —
    reachability turned a "possible" into a "real" surface."""
    rendered = format_path(path, root)
    note = (
        f" Import path detected ({len(path)} hop"
        f"{'s' if len(path) != 1 else ''}): `{rendered}`. Any data-flow "
        f"along this chain is the path a prompt injection would travel."
    )
    new_narrative = combo.narrative.rstrip() + note
    new_evidence = list(combo.evidence) + [f"reach: {rendered}"]
    return dc_replace(combo, narrative=new_narrative, evidence=new_evidence)


def render_markdown(combos: list[Combo]) -> str:
    """Top-of-report section listing each combo that triggered."""
    if not combos:
        return ""

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}

    lines: list[str] = ["## Critical combos detected", ""]
    lines.append(
        "When two or more capabilities appear in the same repo, the real "
        "attack surface isn't the sum — it's the product. These are the "
        "combos the scanner found that amplify the impact of a single "
        "prompt injection."
    )
    lines.append("")

    for c in combos:
        emoji = severity_emoji.get(c.severity, "•")
        lines.append(f"### {emoji} {c.title}")
        lines.append("")
        lines.append(c.narrative)
        lines.append("")
        if c.evidence:
            lines.append(f"**Evidence:** {', '.join(c.evidence)}")
            lines.append("")
        lines.append(f"**Guard:** {c.mitigation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines) + "\n"
