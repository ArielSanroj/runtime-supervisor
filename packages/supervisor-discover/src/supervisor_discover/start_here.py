"""Vibe-coder entry view — what the dev sees first after a scan.

Answers four questions, in this order:
  1. Where do I add the first wrapper?
  2. What can this repo already do in the real world?
  3. What's the highest-risk chain if an LLM reaches those call-sites?
  4. What should I ignore for now?

The data structure is built from RepoSummary + raw findings. The CLI renders it
as 5-10 stdout lines; START_HERE.md renders it as the first markdown artifact;
the web UI consumes it via the API. Single source of truth: this module.

No security jargon in any user-facing string here. Headlines and bullets MUST
not contain words from the policy's `forbidden_words` list (OWASP, CVSS, RCE-
equivalent, exfiltration, account takeover) — that's enforced by
test_communication_rules.py.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .findings import Finding
from .policy_loader import load_scan_output_policy
from .summary import RepoSummary, chokepoint_rank


@dataclass(frozen=True)
class WrapTarget:
    """One concrete place to drop @supervised first."""
    label: str          # "AlertDispatcher" or "AlertDispatcher.dispatch"
    file: str           # absolute path (UI strips to relative)
    line: int           # 1-indexed
    why: str            # "central tool router — one wrapper here covers all tools"


@dataclass(frozen=True)
class Risk:
    """One thing the agent could do that the dev should think about now.

    Three-part structure mandated by docs/SCAN_COMMUNICATION_RULES.md:
      confirmed_in_code → what the scanner saw, with file:line
      possible_chain    → "if LLM/user-controlled text reaches this..."
      do_this_now       → one concrete next step
    """
    title: str
    confirmed_in_code: str
    possible_chain: str
    do_this_now: str
    family: str         # internal key for sorting / UI tone


@dataclass(frozen=True)
class StartHere:
    top_wrap_targets: list[WrapTarget] = field(default_factory=list)
    repo_capabilities: list[str] = field(default_factory=list)
    top_risks: list[Risk] = field(default_factory=list)
    do_this_now: str = ""                       # markdown snippet — code block + 1 line
    hidden_counter: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── builder ──────────────────────────────────────────────────────────


# Risk titles + chain copy keyed by (scanner, family). The phrasing follows the
# "confirmed in code / possible chain / do this now" pattern. Keep headlines
# free of OWASP / CVSS / RCE / exfiltration / account-takeover jargon.
_RISK_CARDS: dict[str, dict[str, str]] = {
    "fs-shell-shell-exec": {
        "title": "Shell execution present",
        "chain": "If an LLM or user-controlled text reaches this call-site, "
                 "it could run host commands.",
        "do":    "Wrap this with `@supervised(\"tool_use\")` and require an "
                 "explicit allowlist of commands.",
    },
    "fs-shell-fs-delete": {
        "title": "File delete present",
        "chain": "Injected prompts could wipe temp dirs, logs, or data the "
                 "agent has write access to.",
        "do":    "Wrap with `@supervised(\"tool_use\")` and constrain paths to "
                 "an allowlist.",
    },
    "fs-shell-fs-write": {
        "title": "File write present",
        "chain": "Agent-driven writes can clobber configs or plant payloads if "
                 "the path comes from model output.",
        "do":    "Wrap and pin destination paths to a known directory.",
    },
    "payment-calls": {
        "title": "Money movement present",
        "chain": "If the agent decides amounts or recipients, a small prompt "
                 "twist becomes a real charge.",
        "do":    "Wrap with `@supervised(\"payment\")` and add a per-call cap.",
    },
    "email-sends": {
        "title": "Email sending present",
        "chain": "If the agent controls recipient + body, this can become "
                 "phishing on your domain's reputation.",
        "do":    "Wrap with `@supervised(\"tool_use\")` and add recipient caps "
                 "+ review for bulk sends.",
    },
    "messaging": {
        "title": "Messaging tools present",
        "chain": "Agent-driven Slack/Discord/SMS sends reach real users — "
                 "noisy at best, social-engineering at worst.",
        "do":    "Wrap and rate-limit per channel.",
    },
    "voice-actions": {
        "title": "Voice / telephony present",
        "chain": "Outbound calls or SMS triggered by an agent can carry "
                 "regulatory cost if mis-targeted.",
        "do":    "Wrap with `@supervised(\"tool_use\")` and require human "
                 "confirmation for new numbers.",
    },
    "calendar-actions": {
        "title": "Calendar mutations present",
        "chain": "Agent-driven calendar writes can leak meeting metadata or "
                 "spam attendees.",
        "do":    "Wrap and constrain to a single calendar by default.",
    },
    "db-mutations-write": {
        "title": "Database writes present",
        "chain": "If the agent chooses what to insert/update, malformed input "
                 "can corrupt rows or escalate state.",
        "do":    "Wrap with `@supervised(\"data_access\")` and review the "
                 "schema for fields the agent should not touch.",
    },
    "db-mutations-delete": {
        "title": "Database deletes present",
        "chain": "Injected prompts could drop rows the agent reaches.",
        "do":    "Wrap with `@supervised(\"data_access\")` and restrict to "
                 "soft-delete / quota-bounded operations.",
    },
    "llm-calls": {
        "title": "LLM calls present",
        "chain": "Anything the LLM returns can become input to other tools — "
                 "this is the entry point for prompt-injection chains.",
        "do":    "Wrap your LLM call-site (or the dispatcher around it) with "
                 "`@supervised(\"tool_use\")`.",
    },
    "agent-orchestrators": {
        "title": "Agent loop present",
        "chain": "An agent loop that decides which tool to call next is the "
                 "single highest-leverage place to gate.",
        "do":    "Wrap the dispatch / handle / execute method with "
                 "`@supervised(\"tool_use\")`.",
    },
}


def _capability_key(f: Finding) -> str:
    """Map a finding to the capability_phrases / risk_severity / _RISK_CARDS key.

    For fs-shell and db-mutations the family/verb in `extra` matters (delete
    vs write vs shell-exec); for everything else the scanner name is enough.
    """
    extra = f.extra or {}
    if f.scanner == "fs-shell":
        family = extra.get("family") or "shell-exec"
        return f"fs-shell-{family}"
    if f.scanner == "db-mutations":
        verb = (extra.get("verb") or "").lower()
        if verb in ("delete", "drop", "truncate"):
            return "db-mutations-delete"
        return "db-mutations-write"
    return f.scanner


def _wrap_target_label(cp_kind: str, cp_label: str) -> str:
    """Render a wrap target the dev can search for. agent-class → ClassName,
    tool-registration → "tool: <name>", framework-import → framework name."""
    if cp_kind == "agent-class":
        return cp_label
    if cp_kind == "tool-registration":
        return f"tool: {cp_label}"
    if cp_kind == "framework-import":
        return f"{cp_label} framework entrypoint"
    return cp_label


def _wrap_target_why(cp_kind: str, rank_tier: int) -> str:
    """Plain-English rationale for why this wrap target is the best first move."""
    if rank_tier == 0:
        return "central agent class — one wrapper here covers every tool it dispatches"
    if cp_kind == "tool-registration":
        return "tool registered with the framework — wrap the registration site"
    if cp_kind == "agent-class":
        return "agent class — wrap its dispatch / handle / execute method"
    return "framework entrypoint — signals the loop, not the wrap point itself"


def _build_wrap_targets(summary: RepoSummary, max_targets: int) -> list[WrapTarget]:
    """Top N agent_chokepoints by chokepoint_rank, deduplicated by (file, line)."""
    ranked = sorted(summary.agent_chokepoints, key=chokepoint_rank)
    seen: set[tuple[str, int]] = set()
    out: list[WrapTarget] = []
    for cp in ranked:
        key = (cp.file, cp.line)
        if key in seen:
            continue
        seen.add(key)
        rank = chokepoint_rank(cp)
        out.append(WrapTarget(
            label=_wrap_target_label(cp.kind, cp.label),
            file=cp.file,
            line=cp.line,
            why=_wrap_target_why(cp.kind, rank[0]),
        ))
        if len(out) >= max_targets:
            break
    return out


def _build_capabilities(summary: RepoSummary, findings: list[Finding],
                        capability_phrases: dict[str, str]) -> list[str]:
    """Plain-English bullets of what this repo can already do.

    Derived from the capabilities the scanner observed. Ordered for readability:
    money first (highest stakes), then real-world actions, then LLM, then data."""
    seen_phrases: list[str] = []

    def _add(phrase: str | None) -> None:
        if phrase and phrase not in seen_phrases:
            seen_phrases.append(phrase)

    # Money (payments first because stakes)
    if summary.payment_integrations:
        _add(capability_phrases.get("payment-calls"))

    # Real-world actions, in stable order
    rwa_keys_to_scanner = {
        "voice / telephony":              "voice-actions",
        "email sends":                    "email-sends",
        "messaging (slack / discord / sms)": "messaging",
        "calendar events":                "calendar-actions",
        "filesystem / shell exec":        None,   # split into shell-exec/delete/write below
        "generative media":               "media-gen",
    }
    for rwa_label in summary.real_world_actions:
        scanner_key = rwa_keys_to_scanner.get(rwa_label)
        if scanner_key:
            _add(capability_phrases.get(scanner_key))

    # fs-shell needs per-family expansion (capability_phrases has 3 entries)
    fs_families = {(_capability_key(f)) for f in findings if f.scanner == "fs-shell"}
    for fam_key in sorted(fs_families):
        _add(capability_phrases.get(fam_key))

    # LLM
    if summary.llm_providers:
        provider_list = ", ".join(summary.llm_providers[:3])
        _add(f"call LLMs ({provider_list})")

    # DB writes / deletes — split per verb
    db_keys = {_capability_key(f) for f in findings if f.scanner == "db-mutations"}
    for db_key in sorted(db_keys):
        _add(capability_phrases.get(db_key))

    return seen_phrases


def _build_top_risks(findings: list[Finding], policy: dict[str, Any]) -> list[Risk]:
    """One Risk per high-confidence capability key, ordered by risk_severity."""
    risk_severity: dict[str, int] = policy.get("risk_severity") or {}
    max_risks: int = policy.get("max_top_risks") or 3

    # Pick one representative finding per capability key (first high-confidence).
    representative: dict[str, Finding] = {}
    for f in findings:
        if f.confidence != "high":
            continue
        key = _capability_key(f)
        if key not in representative and key in _RISK_CARDS:
            representative[key] = f

    # Order by severity (descending), tie-break by capability key for determinism.
    ordered_keys = sorted(
        representative.keys(),
        key=lambda k: (-risk_severity.get(k, 0), k),
    )

    risks: list[Risk] = []
    for key in ordered_keys[:max_risks]:
        f = representative[key]
        card = _RISK_CARDS[key]
        risks.append(Risk(
            title=card["title"],
            confirmed_in_code=f"`{f.snippet}` at `{_short_path(f.file)}:{f.line}`",
            possible_chain=card["chain"],
            do_this_now=card["do"],
            family=key,
        ))
    return risks


def _build_do_this_now(targets: list[WrapTarget]) -> str:
    """Render the single concrete next step as a markdown snippet block.

    Picks the SDK + syntax based on the wrap target's file extension so a
    `.ts` chokepoint gets a TypeScript snippet (`@runtime-supervisor/guards`)
    and a `.py` chokepoint gets the Python decorator. Defaults to Python
    when extension is unknown.
    """
    if not targets:
        return (
            "No obvious wrap target in this repo. Start with the entry-point "
            "of your agent loop (the function that decides which tool to call)."
        )
    primary = targets[0]
    rel = _short_path(primary.file)
    suffix = Path(primary.file).suffix.lower()
    is_ts = suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs")

    # Function name guess used in both languages
    fn_hint = primary.label.split(".")[-1].split(":")[-1].strip() or "handler"
    fn_hint_safe = "".join(c if c.isalnum() or c == "_" else "_" for c in fn_hint)
    if is_ts:
        # camelCase the underscored name for TS idiom
        camel = "".join(p.capitalize() if i else p for i, p in enumerate(fn_hint_safe.lower().split("_")))
        camel = camel or "handler"
        return (
            f"Wrap **{primary.label}** in `{rel}:{primary.line}`:\n"
            f"\n"
            f"```ts\n"
            f"import {{ supervised }} from \"@runtime-supervisor/guards\";\n"
            f"\n"
            f"export const {camel} = supervised(\"tool_use\", async (...args) => {{\n"
            f"  // original implementation\n"
            f"}});\n"
            f"```"
        )
    return (
        f"Wrap **{primary.label}** in `{rel}:{primary.line}`:\n"
        f"\n"
        f"```python\n"
        f"from supervisor_guards import supervised\n"
        f"\n"
        f"@supervised(\"tool_use\")\n"
        f"def {fn_hint_safe.lower() or 'handler'}(...):\n"
        f"    ...\n"
        f"```"
    )


def _short_path(path: str) -> str:
    """Make a long absolute path readable. Keep the last 3 segments."""
    parts = Path(path).parts
    if len(parts) <= 3:
        return path
    return "/".join(parts[-3:])


def build_start_here(summary: RepoSummary, findings: list[Finding],
                     policy: dict[str, Any] | None = None) -> StartHere:
    """Construct the StartHere data structure from a built summary + findings."""
    p = policy or load_scan_output_policy()
    max_wrap = p.get("max_wrap_targets") or 3
    capability_phrases = p.get("capability_phrases") or {}

    targets = _build_wrap_targets(summary, max_wrap)
    capabilities = _build_capabilities(summary, findings, capability_phrases)
    top_risks = _build_top_risks(findings, p)
    do_now = _build_do_this_now(targets)
    return StartHere(
        top_wrap_targets=targets,
        repo_capabilities=capabilities,
        top_risks=top_risks,
        do_this_now=do_now,
        hidden_counter=dict(summary.hidden_findings),
    )


# ─── renderers ────────────────────────────────────────────────────────


def render_start_here_md(sh: StartHere) -> str:
    """Markdown for runtime-supervisor/START_HERE.md.

    Section order is mandatory (see docs/SCAN_COMMUNICATION_RULES.md):
      1. Best place to wrap first
      2. What this repo can already do
      3. Highest-risk things to care about now
      4. Do this now
      5. Ignore this for now
    """
    parts: list[str] = ["# Start here", ""]

    # 1. wrap targets
    parts.append("## Best place to wrap first")
    parts.append("")
    if sh.top_wrap_targets:
        for i, t in enumerate(sh.top_wrap_targets, 1):
            rel = _short_path(t.file)
            parts.append(f"{i}. **{t.label}** — `{rel}:{t.line}`")
            parts.append(f"   _{t.why}_")
        parts.append("")
        parts.append(
            "_Why this first: one wrapper here covers most current and future tools._"
        )
    else:
        parts.append(
            "No obvious wrap target. Start with the entry-point of your agent "
            "loop (the function that decides which tool to call)."
        )
    parts.append("")

    # 2. capabilities
    parts.append("## What this repo can already do")
    parts.append("")
    if sh.repo_capabilities:
        parts.append("This repo can already:")
        for cap in sh.repo_capabilities:
            parts.append(f"- {cap}")
    else:
        parts.append("No high-stakes capabilities detected in this preview.")
    parts.append("")
    parts.append(
        "_This is a capability statement, not proof that every path is "
        "agent-controlled._"
    )
    parts.append("")

    # 3. top risks
    parts.append("## Highest-risk things to care about now")
    parts.append("")
    if sh.top_risks:
        for r in sh.top_risks:
            parts.append(f"### {r.title}")
            parts.append(f"- Confirmed in code: {r.confirmed_in_code}")
            parts.append(f"- Possible chain: {r.possible_chain}")
            parts.append(f"- Do this now: {r.do_this_now}")
            parts.append("")
    else:
        parts.append(
            "No high-confidence risk patterns surfaced — the repo may not "
            "expose agent-grade integrations yet."
        )
        parts.append("")

    # 4. do this now
    parts.append("## Do this now")
    parts.append("")
    parts.append(sh.do_this_now)
    parts.append("")
    parts.append("Then read `runtime-supervisor/FULL_REPORT.md` for the full breakdown.")
    parts.append("")

    # 5. ignore
    parts.append("## Ignore this for now")
    parts.append("")
    parts.append("Ignore for now:")
    parts.append("- HTTP route inventory")
    parts.append("- medium- and low-confidence findings")
    parts.append("- informational inventory")
    parts.append("- tests / legacy / migrations / generated code")
    parts.append("")
    if sh.hidden_counter:
        total = sum(sh.hidden_counter.values())
        breakdown = ", ".join(
            f"{n} {cat}" for cat, n in sorted(sh.hidden_counter.items())
        )
        parts.append(f"_{total} findings hidden ({breakdown}). Open `FULL_REPORT.md` for the full set._")
    else:
        parts.append("_If you need everything, open `FULL_REPORT.md`._")
    parts.append("")

    return "\n".join(parts)


def render_cli_start_here(sh: StartHere, *, elapsed_s: float | None = None,
                          root: str | None = None) -> list[str]:
    """5-10 line block for the terminal. Replaces the old tier-row dump.

    Format mirrors the spec:
        scanned <root> in <T>s

        Best place to wrap first:
        1. <label>      <file>:<line>

        This repo can already:
        - <capability>

        Top risks:
        - <risk title>

        Next:
           open runtime-supervisor/START_HERE.md      ← do this first
           runtime-supervisor/FULL_REPORT.md          ← all findings
           runtime-supervisor/ROLLOUT.md              ← phased deploy
    """
    out: list[str] = []
    if elapsed_s is not None:
        target = root or "."
        out.append(f"scanned {target} in {elapsed_s:.1f}s")
        out.append("")

    out.append("Best place to wrap first:")
    if sh.top_wrap_targets:
        for i, t in enumerate(sh.top_wrap_targets, 1):
            rel = _short_path(t.file)
            out.append(f"  {i}. {t.label:<28s}  {rel}:{t.line}")
    else:
        out.append("  (no obvious wrap target — start at your agent loop's entry-point)")
    out.append("")

    out.append("This repo can already:")
    if sh.repo_capabilities:
        for cap in sh.repo_capabilities[:6]:
            out.append(f"  - {cap}")
    else:
        out.append("  - (no high-stakes capabilities detected)")
    out.append("")

    out.append("Top risks:")
    if sh.top_risks:
        for r in sh.top_risks:
            out.append(f"  - {r.title.lower()}")
    else:
        out.append("  - (none surfaced at high confidence)")
    out.append("")

    out.append("Next:")
    out.append("  open runtime-supervisor/START_HERE.md      ← do this first")
    out.append("  runtime-supervisor/FULL_REPORT.md          ← all findings")
    out.append("  runtime-supervisor/ROLLOUT.md              ← phased deploy")

    return out
