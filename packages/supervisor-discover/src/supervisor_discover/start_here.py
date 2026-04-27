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

import ast

from .bootstrap import BootstrapInfo, build_bootstrap_info
from .findings import Finding
from .policy_loader import load_scan_output_policy
from .scanners._utils import parse_python, safe_read
from .summary import RepoSummary, chokepoint_rank, is_low_reachability_path


@dataclass(frozen=True)
class WrapTarget:
    """One concrete place to drop @supervised first."""
    label: str          # "AlertDispatcher" or "AlertDispatcher.dispatch"
    file: str           # absolute path (UI strips to relative)
    line: int           # 1-indexed
    why: str            # "central tool router — one wrapper here covers all tools"
    # Names of peer dispatch methods (when the class has ≥2 like
    # `dispatch_sla_alert`, `dispatch_deadline_alert`). Empty tuple for the
    # normal single-entry-point case. The renderer uses this to flip the copy
    # from "one wrapper covers all" to "wrap each of N methods".
    parallel_methods: tuple[str, ...] = ()


@dataclass(frozen=True)
class FrameworkSignal:
    """An agent framework detected in the repo (langchain / langgraph / autogen
    / crewai / mastra). The import line itself is NOT a wrap point — the wrap
    point is the framework's dispatch method or the tool callable it invokes.
    Surfaced separately from WrapTarget so the "Best place to wrap first"
    section never lists a non-wrappable line."""
    framework: str      # "langchain", "langgraph", "autogen", "crewai", "mastra"
    file: str           # absolute path (UI strips to relative)
    line: int           # 1-indexed
    snippet: str        # the matched code so the dev can search for it


@dataclass(frozen=True)
class Risk:
    """One thing the agent could do that the dev should think about now.

    Three-part structure mandated by docs/SCAN_COMMUNICATION_RULES.md:
      confirmed_in_code → what the scanner saw, with file:line
      possible_chain    → "if LLM/user-controlled text reaches this..."
      do_this_now       → one concrete next step
      example           → fenced code block showing the wrap, derived from
                          the finding's enclosing function (empty when the
                          file isn't .py / can't be parsed / call is at
                          module scope)
    """
    title: str
    confirmed_in_code: str
    possible_chain: str
    do_this_now: str
    family: str         # internal key for sorting / UI tone
    example: str = ""   # markdown fenced code block, "" when not derivable


@dataclass(frozen=True)
class StartHere:
    top_wrap_targets: list[WrapTarget] = field(default_factory=list)
    repo_capabilities: list[str] = field(default_factory=list)
    top_risks: list[Risk] = field(default_factory=list)
    do_this_now: str = ""                       # markdown snippet — code block + 1 line
    hidden_counter: dict[str, int] = field(default_factory=dict)
    # Agent frameworks detected via import patterns (langchain, langgraph, …).
    # Informational — these are loop signals, not wrap points.
    framework_signals: list[FrameworkSignal] = field(default_factory=list)
    # Step 0 metadata — how to install the SDK and where to drop
    # `configure_supervisor()`. None when no manifest was detected; the
    # renderer falls back to a generic block in that case.
    bootstrap: BootstrapInfo | None = None
    # When the scanned repo is itself a framework / SDK (langchain,
    # llamaindex, etc.), the chokepoints are *consumer integration
    # surfaces*, not deployed wrap points. The renderer prepends a banner
    # to keep the user from acting on the report as if it were their app.
    repo_kind: str = "unknown"

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
    "fs-shell-code-eval": {
        "title": "Code execution via `eval` / `exec` present",
        "chain": "If the string passed to `eval` / `exec` flows from an LLM "
                 "or user input, the agent runs arbitrary code in this "
                 "process — same blast radius as a shell.",
        "do":    "Wrap with `@supervised(\"tool_use\")` and validate the "
                 "source first; better, replace with `ast.literal_eval` or "
                 "a parsed expression evaluator for the trusted-input case.",
    },
    "fs-shell-unsafe-deserialize": {
        "title": "Pickle / dill deserialization present",
        "chain": "`pickle.loads` rebuilds objects via `__reduce__` gadgets — "
                 "untrusted bytes here become a code-execution primitive.",
        "do":    "Wrap with `@supervised(\"tool_use\")`; for untrusted "
                 "input switch to JSON or msgpack with an explicit schema.",
    },
    "auth-bypass-tls-bypass": {
        "title": "TLS verification disabled present",
        "chain": "An attacker on the network path (rogue Wi-Fi, intercepted "
                 "CI runner, mistakenly imported dev cert) becomes a silent "
                 "man-in-the-middle on every request from this site.",
        "do":    "Remove `verify=False` and pin a CA bundle; if you need a "
                 "self-signed dev cert, gate it behind an env-only branch.",
    },
    "auth-bypass-jwt-bypass": {
        "title": "JWT signature check disabled present",
        "chain": "The decoder accepts any token, so every `if user_role == "
                 "'admin'` downstream becomes a free-for-all — the attacker "
                 "writes the claims they want.",
        "do":    "Stop bypassing the signature. If the token is genuinely "
                 "untrusted, reject it instead of decoding it without "
                 "verification.",
    },
    "db-mutations-redis-flush": {
        "title": "Redis keyspace wipe present",
        "chain": "`flushall` / `flushdb` clears every key with no rollback. "
                 "Inside an agent loop this is data loss on a prompt twist.",
        "do":    "Wrap with `@supervised(\"data_access\")` and require an "
                 "explicit operator confirmation before flushing.",
    },
}


def _capability_key(f: Finding) -> str:
    """Map a finding to the capability_phrases / risk_severity / _RISK_CARDS key.

    For fs-shell, auth-bypass, and db-mutations the family/verb in `extra`
    matters (delete vs write vs shell-exec, tls-bypass vs jwt-bypass, etc.);
    for everything else the scanner name is enough.
    """
    extra = f.extra or {}
    if f.scanner == "fs-shell":
        family = extra.get("family") or "shell-exec"
        return f"fs-shell-{family}"
    if f.scanner == "auth-bypass":
        family = extra.get("family") or "tls-bypass"
        return f"auth-bypass-{family}"
    if f.scanner == "db-mutations":
        verb = (extra.get("verb") or "").lower()
        family = (extra.get("family") or "").lower()
        if family == "redis-flush":
            return "db-mutations-redis-flush"
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


def _wrap_target_why(cp_kind: str, rank_tier: int,
                     parallel_methods: tuple[str, ...] = ()) -> str:
    """Plain-English rationale for why this wrap target is the best first move.

    Only invoked for chokepoints that survived the framework-import filter in
    `_build_wrap_targets`, so `cp_kind` is always "agent-class" or
    "tool-registration".

    When the class has ≥2 peer dispatch methods (`AlertDispatcher` with
    `dispatch_sla_alert`, `dispatch_deadline_alert`, …), the "one wrapper
    covers all" claim is FALSE — each method is a separate public entry. The
    copy flips to acknowledge this so the dev wraps each one (or refactors
    through a common helper).
    """
    if parallel_methods:
        n = len(parallel_methods)
        first = ", ".join(parallel_methods[:3])
        suffix = ", …" if n > 3 else ""
        return (
            f"class with {n} peer dispatch methods ({first}{suffix}) — "
            f"wrap each one, or refactor through a shared helper"
        )
    if rank_tier == 0:
        return "central agent class — one wrapper here covers every tool it dispatches"
    if cp_kind == "tool-registration":
        return "tool registered with the framework — wrap the registration site"
    return "agent class — wrap its dispatch / handle / execute method"


def _build_wrap_targets(
    summary: RepoSummary,
    max_targets: int,
    findings: list[Finding] | None = None,
) -> list[WrapTarget]:
    """Top N actionable agent_chokepoints by chokepoint_rank, deduplicated by
    (file, line).

    Excludes:
      - `kind == "framework-import"` (loop signal, not a wrap point — surfaces
        in `StartHere.framework_signals`).
      - chokepoints under low-reachability paths (test/setup/scripts/legacy).
        They remain in FULL_REPORT but never reach the "do this now" top.
      - chokepoints whose underlying finding was tagged as `suppressed` by
        `.supervisor-ignore`. The dev explicitly said "don't surface this".
    """
    suppressed_locs: set[tuple[str, int]] = set()
    # Map class name → parent class name. Built by `agent_graph.annotate_findings`
    # at scan time; the parent_agent flag is on each child finding's `extra`.
    # We rebuild a label-keyed map here so the chokepoint loop can demote
    # children whose parent is also in the chokepoint set.
    parent_of: dict[str, str] = {}
    if findings:
        for f in findings:
            extra = f.extra or {}
            if extra.get("suppressed"):
                suppressed_locs.add((f.file, f.line))
            parent = extra.get("parent_agent")
            if parent and extra.get("kind") == "agent-class":
                cls_name = extra.get("class_name")
                if cls_name:
                    parent_of[str(cls_name)] = str(parent)

    actionable_pre_graph = [
        cp for cp in summary.agent_chokepoints
        if cp.kind != "framework-import"
        and not is_low_reachability_path(cp.file)
        and (cp.file, cp.line) not in suppressed_locs
    ]
    # Drop children whose parent is also in the chokepoint set: the parent
    # covers them transitively (the parent's __init__ instantiates the
    # child, so wrapping the parent's dispatch method gates the child too).
    parent_labels = {cp.label for cp in actionable_pre_graph}
    actionable = [
        cp for cp in actionable_pre_graph
        if not (cp.kind == "agent-class" and parent_of.get(cp.label) in parent_labels)
    ]
    ranked = sorted(actionable, key=chokepoint_rank)
    seen: set[tuple[str, int]] = set()
    out: list[WrapTarget] = []
    for cp in ranked:
        key = (cp.file, cp.line)
        if key in seen:
            continue
        seen.add(key)
        rank = chokepoint_rank(cp)
        # `chokepoint_rank` adds +10 for low-reachability paths; the actual
        # tier (the wrappability bucket the why-string is keyed on) is the
        # base rank without that demotion.
        base_tier = rank[0] % 10
        out.append(WrapTarget(
            label=_wrap_target_label(cp.kind, cp.label),
            file=cp.file,
            line=cp.line,
            why=_wrap_target_why(cp.kind, base_tier, cp.parallel_methods),
            parallel_methods=cp.parallel_methods,
        ))
        if len(out) >= max_targets:
            break
    return out


def _build_framework_signals(
    summary: RepoSummary,
    findings: list[Finding],
    max_signals: int = 5,
) -> list[FrameworkSignal]:
    """Collect framework-import chokepoints into FrameworkSignal records.

    Joins on (file, line) against agent-orchestrators findings to recover the
    framework name (from `extra["framework"]`) and the original snippet, so the
    rendered markdown can show the exact line the dev needs to search for.
    Dedup by (framework, file, line). Cap at `max_signals` to keep the section
    skimmable.
    """
    finding_index: dict[tuple[str, int], Finding] = {}
    for f in findings:
        if f.scanner != "agent-orchestrators":
            continue
        if (f.extra or {}).get("kind") != "framework-import":
            continue
        finding_index.setdefault((f.file, f.line), f)

    seen: set[tuple[str, str, int]] = set()
    out: list[FrameworkSignal] = []
    # Reachable chokepoints first; if there are none, fall back to all of them
    # so the dev still sees that the framework exists in the repo (the ones in
    # test/setup paths get a special note via the renderer).
    reachable_first = sorted(
        (cp for cp in summary.agent_chokepoints if cp.kind == "framework-import"),
        key=lambda cp: (is_low_reachability_path(cp.file), cp.file, cp.line),
    )
    for cp in reachable_first:
        f = finding_index.get((cp.file, cp.line))
        framework = (f.extra or {}).get("framework") if f else None
        framework = framework or cp.label or "agent framework"
        key = (framework, cp.file, cp.line)
        if key in seen:
            continue
        seen.add(key)
        snippet = f.snippet if f else ""
        out.append(FrameworkSignal(
            framework=framework,
            file=cp.file,
            line=cp.line,
            snippet=snippet,
        ))
        if len(out) >= max_signals:
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

    # DB writes / deletes — split per verb (also surfaces redis-flush)
    db_keys = {_capability_key(f) for f in findings if f.scanner == "db-mutations"}
    for db_key in sorted(db_keys):
        _add(capability_phrases.get(db_key))

    # Auth / TLS bypass — split per family
    auth_keys = {_capability_key(f) for f in findings if f.scanner == "auth-bypass"}
    for auth_key in sorted(auth_keys):
        _add(capability_phrases.get(auth_key))

    return seen_phrases


def _risk_wrap_example(f: Finding) -> str:
    """Render a copy-paste wrap example for the function enclosing `f.line`.

    Walks the file's AST to find the innermost FunctionDef / AsyncFunctionDef
    that contains the finding's line. Renders a 5-line markdown code block
    with `@supervised(<f.suggested_action_type>)` over that function's real
    signature. The dev can paste it on top of their existing function — the
    body is elided as `...` so we don't pretend to rewrite their code.

    Returns "" when the file isn't .py / .ipynb, can't be read or parsed,
    or the call lives at module scope (no enclosing def). The card-renderer
    treats empty as "skip the example row".
    """
    suffix = Path(f.file).suffix.lower()
    if suffix not in (".py", ".ipynb"):
        return ""
    text = safe_read(Path(f.file))
    if text is None:
        return ""
    tree = parse_python(text)
    if tree is None:
        return ""

    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        if not (node.lineno <= f.line <= end):
            continue
        # Innermost wins (e.g., a method inside a class wrapping a helper def).
        if enclosing is None or node.lineno > enclosing.lineno:
            enclosing = node

    if enclosing is None:
        return ""

    action_type = f.suggested_action_type or "tool_use"
    keyword = "async def" if isinstance(enclosing, ast.AsyncFunctionDef) else "def"
    args_repr = _format_python_args(enclosing.args)
    rel = _short_path(f.file)
    return (
        f"```python\n"
        f"from supervisor_guards import supervised\n"
        f"\n"
        f"@supervised(\"{action_type}\")\n"
        f"{keyword} {enclosing.name}({args_repr}):  # {rel}:{enclosing.lineno}\n"
        f"    ...\n"
        f"```"
    )


def _build_top_risks(findings: list[Finding], policy: dict[str, Any]) -> list[Risk]:
    """One Risk per high-confidence capability key, ordered by risk_severity.

    Skip findings that:
      - aren't high confidence,
      - live on low-reachability paths (test/setup/scripts/legacy) — a
        `subprocess.run` in `setup.py` is real code but not the agent's runtime
        path,
      - are already wrapped (`extra.already_gated == True`) — the user has
        a `@supervised(...)` or a `guarded(...)` covering this call-site, so
        rendering "do this now: wrap it" is wrong.

    Such findings stay in FULL_REPORT for completeness.
    """
    risk_severity: dict[str, int] = policy.get("risk_severity") or {}
    max_risks: int = policy.get("max_top_risks") or 3

    representative: dict[str, Finding] = {}
    for f in findings:
        if f.confidence != "high":
            continue
        if is_low_reachability_path(f.file):
            continue
        if (f.extra or {}).get("already_gated"):
            continue
        if (f.extra or {}).get("suppressed"):
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
            example=_risk_wrap_example(f),
        ))
    return risks


# Method names to prefer as the "main" wrap point inside an agent class, in
# priority order. The first match wins. Falls back to the first public method
# if none of these are present.
#
# Includes langchain idioms (`plan` / `aplan`) so the picker doesn't fall
# through to "first public method" on classes whose first def is a `@property`
# (e.g. `XMLAgent.input_keys`) — that produced "wrap input_keys" snippets
# that did nothing at runtime.
_PRIMARY_METHOD_PREFERENCE = (
    "handle", "execute", "dispatch", "run",
    "process", "route", "invoke", "call", "step",
    "plan", "aplan", "ainvoke", "arun",
    "reason", "decide", "orchestrate",
)


# Method decorators that mean "do not put @supervised here" — wrapping these
# either has no runtime effect or applies the gate to metadata, not behaviour:
# - `@property` returns a value at attribute access; the dev expects to wrap a
#   *method invocation*, not a getter. (`XMLAgent.input_keys` was the symptom
#   that surfaced this.)
# - `@classmethod` / `@staticmethod` aren't bound to instances; the gate often
#   needs `self` to read tenant/user context. Skip and let the picker find a
#   real instance method.
# - `@abstractmethod` and `abc.abstractmethod` declare an interface — the body
#   is contract-only, subclasses don't inherit decorators applied to abstracts.
_SKIP_METHOD_DECORATOR_NAMES = frozenset({
    "property",
    "classmethod",
    "staticmethod",
    "abstractmethod", "abc.abstractmethod",
    "abstractproperty", "abc.abstractproperty",
    "abstractclassmethod", "abc.abstractclassmethod",
    "abstractstaticmethod", "abc.abstractstaticmethod",
    "cached_property", "functools.cached_property",
})


def _decorator_dotted(node: ast.expr) -> str | None:
    """Render a decorator AST node as a dotted name. Handles `@foo`,
    `@foo.bar`, and the call form `@foo("0.1.0")`."""
    target = node.func if isinstance(node, ast.Call) else node
    parts: list[str] = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _method_is_skippable(method: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when `method` carries a decorator that disqualifies it as a
    `@supervised` target — properties, class/static methods, abstracts."""
    for dec in method.decorator_list:
        dotted = _decorator_dotted(dec)
        if dotted is None:
            continue
        bare = dotted.rsplit(".", 1)[-1]
        if dotted in _SKIP_METHOD_DECORATOR_NAMES or bare in _SKIP_METHOD_DECORATOR_NAMES:
            return True
    return False

# Variable names that, when used as the LHS of a comparison or as the subject
# of a `match` statement, indicate "this method routes by a label produced
# upstream (likely by an LLM)". Used to identify the actual dispatcher method
# inside an agent class — the reviewer flagged that the previous heuristic
# picked methods named `handle` even when the real dispatcher was
# `_execute_action(self, decision)` with `if action == AgentAction.X` inside.
_DISPATCH_DECISION_KEYS = frozenset({
    "action", "intent", "tool", "kind", "type", "command",
    "operation", "step", "task_type", "verb",
})


def _decision_case_count(method: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """How many times the method's body branches on a decision key.

    Examples that count:
      - `if action == "create": …`            (Compare on a Name in keys)
      - `if action in ("a", "b"): …`          (Compare on a Name in keys)
      - `match decision.action: case …`       (Match on Attribute whose attr is in keys)
      - `if self.intent == "x": …`            (Compare on Attribute whose attr is in keys)

    Walked over the entire method body so nested if/elif chains all count.
    Returns 0 for methods that never reference a decision key — those are
    not dispatchers in the agent sense, regardless of name.
    """
    count = 0
    for node in ast.walk(method):
        if isinstance(node, ast.Compare):
            left = node.left
            if isinstance(left, ast.Name) and left.id in _DISPATCH_DECISION_KEYS:
                count += 1
            elif isinstance(left, ast.Attribute) and left.attr in _DISPATCH_DECISION_KEYS:
                count += 1
        elif isinstance(node, ast.Match):
            subj = node.subject
            if isinstance(subj, ast.Name) and subj.id in _DISPATCH_DECISION_KEYS:
                count += len(node.cases)
            elif isinstance(subj, ast.Attribute) and subj.attr in _DISPATCH_DECISION_KEYS:
                count += len(node.cases)
    return count


def _format_python_args(args: ast.arguments) -> str:
    """Render an `ast.arguments` node back into a Python parameter list.

    Used for the "do this now" snippet so we show the dev's REAL method
    signature (e.g. `(self, decision: Decision)`) rather than a generic
    `(...)`. Annotation rendering uses ast.unparse when available.
    """
    return ast.unparse(args) if hasattr(ast, "unparse") else "..."


def _pick_method_for_wrap(
    cls: ast.ClassDef,
    parallel_methods: tuple[str, ...],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Choose the best method on `cls` to put `@supervised` on.

    Order:
      1. If parallel methods were detected, return the first one (renderer
         tells the user to repeat for the rest).
      2. AST-based: pick the method whose body branches on a decision key
         (`if action == X` / `match action: case ...`). Wins over name-based
         heuristics because it identifies the *actual* dispatcher — the
         reviewer's complaint on castor-1 was that the snippet pointed at
         `handle()` (which doesn't exist) instead of the real
         `_execute_action(self, decision)` with `if action == AgentAction.X`.
      3. Name-based preference: handle / execute / dispatch / run / ….
      4. First public method that isn't `__init__`.
    """
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for child in cls.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _method_is_skippable(child):
                continue
            methods[child.name] = child

    if parallel_methods:
        for name in parallel_methods:
            node = methods.get(name)
            if node is not None:
                return node

    # Decision-branching: look for the method that routes by an LLM-supplied
    # label. Highest case count wins; tie-break by line so the earlier method
    # in source order wins (typically the public entrypoint).
    branching = [
        (name, node, _decision_case_count(node))
        for name, node in methods.items()
    ]
    branching = [(n, m, c) for n, m, c in branching if c > 0]
    if branching:
        branching.sort(key=lambda item: (-item[2], item[1].lineno))
        return branching[0][1]

    for name in _PRIMARY_METHOD_PREFERENCE:
        node = methods.get(name)
        if node is not None:
            return node

    for name, node in methods.items():
        if name.startswith("_"):
            continue
        return node

    return None


def _python_wrap_snippet(target: WrapTarget) -> str | None:
    """Generate a Python snippet that wraps the REAL method at the wrap target.

    Returns None when:
      - the file isn't .py / .ipynb,
      - the file can't be parsed,
      - no class matching the label is found,
      - the class has no obvious method to wrap.

    The caller then falls back to the generic placeholder snippet.
    """
    suffix = Path(target.file).suffix.lower()
    if suffix not in (".py", ".ipynb"):
        return None
    text = safe_read(Path(target.file))
    if text is None:
        return None
    tree = parse_python(text)
    if tree is None:
        return None

    # Class label may be `ToolRegistrationLike "tool: foo"` for
    # tool-registration kind. Strip that prefix.
    label = target.label.split(":", 1)[-1].strip()

    target_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == label:
            # Prefer the class whose body covers the reported line.
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            if node.lineno <= target.line <= end:
                target_class = node
                break
            if target_class is None:
                target_class = node
    if target_class is None:
        return None

    method = _pick_method_for_wrap(target_class, target.parallel_methods)
    if method is None:
        return None

    rel = _short_path(target.file)
    is_async = isinstance(method, ast.AsyncFunctionDef)
    keyword = "async def" if is_async else "def"
    args_repr = _format_python_args(method.args)

    header = f"Wrap **{label}.{method.name}** in `{rel}:{method.lineno}`:"
    if target.parallel_methods and len(target.parallel_methods) > 1:
        others = ", ".join(target.parallel_methods[1:4])
        more = f" (+{len(target.parallel_methods) - 4} more)" if len(target.parallel_methods) > 4 else ""
        header = (
            f"Wrap **{label}.{method.name}** in `{rel}:{method.lineno}` — and "
            f"repeat for the {len(target.parallel_methods) - 1} peer method(s) "
            f"({others}{more}):"
        )

    return (
        f"{header}\n"
        f"\n"
        f"```python\n"
        f"from supervisor_guards import supervised\n"
        f"\n"
        f"class {label}:\n"
        f"    @supervised(\"tool_use\")\n"
        f"    {keyword} {method.name}({args_repr}):\n"
        f"        ...\n"
        f"```"
    )


def _build_do_this_now(
    targets: list[WrapTarget],
    framework_signals: list[FrameworkSignal] | None = None,
    repo_kind: str = "unknown",
) -> str:
    """Render the single concrete next step as a markdown snippet block.

    Picks the SDK + syntax based on the wrap target's file extension so a
    `.ts` chokepoint gets a TypeScript snippet (`@runtime-supervisor/guards`)
    and a `.py` chokepoint gets the Python decorator. Defaults to Python
    when extension is unknown.

    When `targets` is empty but a framework signal is present (e.g. the repo
    only has `from langchain.agents import …`), point at that file with a
    concrete next step instead of the generic empty-state copy.

    When `repo_kind == "framework"` (the langchain shape — see
    `repo_kind.py`), the wrap recommendation is inverted: the consumers
    of this package — not this codebase — are the ones that need wraps.
    The returned copy points the maintainer at the threat-model-for-
    consumers playbook instead of suggesting they decorate a class that
    ships to thousands of downstream apps.
    """
    if repo_kind == "framework":
        cap_lines: list[str] = []
        if targets:
            primary = targets[0]
            cap_lines.append(
                f"Top symbol detected: **{primary.label}** in "
                f"`{_short_path(primary.file)}:{primary.line}`. Document "
                f"the threat model on its public API; wrapping it here only "
                f"protects callers that import this build of the package."
            )
        signals = framework_signals or []
        if signals:
            sig = signals[0]
            cap_lines.append(
                f"Framework presence: `{sig.framework}` at "
                f"`{_short_path(sig.file)}:{sig.line}`. Surface this in your "
                f"docs so consumers know which loop they need to gate."
            )
        if not cap_lines:
            cap_lines.append(
                "No agent-shaped class to wrap directly. Document which "
                "public APIs run an LLM loop, and link consumers to the "
                "runtime-supervisor wrap guide."
            )
        guidance = (
            "This repo looks like a **library or framework** — a distributable "
            "package, not a deployed agent. `@supervised` belongs in the "
            "consumer's agent loop, not in the library code itself."
        )
        body = "\n\n".join([guidance, *cap_lines])
        next_step = (
            "**Do this now (maintainer):** ship a `THREAT_MODEL.md` listing "
            "(a) which public APIs invoke an LLM, (b) which trigger real-world "
            "side effects (shell, filesystem, payments), and (c) the "
            "recommended `@supervised(...)` wrap point on the consumer side."
        )
        return f"{body}\n\n{next_step}"
    if not targets:
        signals = framework_signals or []
        if signals:
            sig = signals[0]
            rel = _short_path(sig.file)
            return (
                f"No agent class or tool registration to point at directly. "
                f"`{sig.framework}` runs the loop in `{rel}:{sig.line}` — "
                f"the wrap point is the tool callable passed to it (e.g. the "
                f"function inside a `Tool(func=…)`) or the function that calls "
                f"`agent.run(...)` / `AgentExecutor.invoke(...)`. "
                f"Open `runtime-supervisor/FULL_REPORT.md` for the full list "
                f"of detected callables."
            )
        return (
            "No obvious wrap target in this repo. Start with the entry-point "
            "of your agent loop (the function that decides which tool to call)."
        )
    primary = targets[0]
    # Try to render a snippet from the real method signature first.
    ast_snippet = _python_wrap_snippet(primary)
    if ast_snippet is not None:
        return ast_snippet
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
                     policy: dict[str, Any] | None = None,
                     *, repo_root: Path | None = None) -> StartHere:
    """Construct the StartHere data structure from a built summary + findings.

    `repo_root`, when provided, enables Step 0 detection (install command +
    `configure_supervisor()` location). Calls don't need to pass it — older
    callers keep working with `bootstrap=None`.
    """
    p = policy or load_scan_output_policy()
    max_wrap = p.get("max_wrap_targets") or 3
    capability_phrases = p.get("capability_phrases") or {}

    targets = _build_wrap_targets(summary, max_wrap, findings)
    framework_signals = _build_framework_signals(summary, findings)
    capabilities = _build_capabilities(summary, findings, capability_phrases)
    top_risks = _build_top_risks(findings, p)
    bootstrap = _build_bootstrap(repo_root, targets) if repo_root is not None else None
    do_now = _build_do_this_now(targets, framework_signals, summary.repo_kind)
    return StartHere(
        top_wrap_targets=targets,
        repo_capabilities=capabilities,
        top_risks=top_risks,
        do_this_now=do_now,
        hidden_counter=dict(summary.hidden_findings),
        framework_signals=framework_signals,
        bootstrap=bootstrap,
        repo_kind=summary.repo_kind,
    )


def _build_bootstrap(repo_root: Path, targets: list[WrapTarget]) -> BootstrapInfo:
    """Pick a language hint from the top wrap target's file extension and ask
    `bootstrap.build_bootstrap_info` to assemble the Step 0 data. The
    language hint matters in monorepos where both Python and JS manifests
    are present — the Step 0 block should match the language of the first
    wrap recommendation."""
    near_files = [t.file for t in targets[:3] if t.file]
    prefer_language: str | None = None
    if targets:
        suffix = Path(targets[0].file).suffix.lower()
        if suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
            prefer_language = "ts"
        elif suffix in (".py", ".ipynb"):
            prefer_language = "python"
    return build_bootstrap_info(
        repo_root,
        prefer_language=prefer_language,
        near_files=near_files,
    )


# ─── renderers ────────────────────────────────────────────────────────


_LANGUAGE_LABEL = {
    "python": "Python",
    "ts": "TypeScript / JavaScript",
}

_FRAMEWORK_LABEL = {
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "starlette": "Starlette",
    "hono": "Hono",
    "express": "Express",
    "deno-serve": "Deno.serve",
    "nestjs": "NestJS",
    "nextjs-handler": "Next.js handler",
    "generic": "your app",
}


def _render_step0(sh: StartHere) -> list[str]:
    """Markdown lines for the Step 0 section. Returns [] when bootstrap is
    `None` (preserves the previous output exactly when the caller doesn't
    pass `repo_root`)."""
    if sh.bootstrap is None:
        return []
    bs = sh.bootstrap
    out: list[str] = ["## Step 0 — install the SDK", ""]

    if bs.manager is None:
        # No manifest detected — generic block, never crashes.
        out.append(
            "We couldn't classify the dep manager from the repo root. Add "
            "`supervisor-guards` (Python) or `@runtime-supervisor/guards` "
            "(TS/JS) using your usual package manager."
        )
    else:
        lang_label = _LANGUAGE_LABEL.get(bs.manager.language, bs.manager.language)
        rel = _short_path(bs.manager.manifest_path)
        out.append(f"Detected: {lang_label} project (`{rel}`).")
        out.append("")
        fence = "bash"
        out.append(f"```{fence}")
        out.append(bs.manager.install_cmd)
        out.append("```")

    if bs.entrypoint is None:
        out.append("")
        out.append(
            "Then call `configure_supervisor()` once at startup, where you "
            "instantiate your app (e.g. next to `FastAPI(...)` / `new Hono()`)."
        )
    elif bs.configure_already_called:
        out.append("")
        ep_rel = _short_path(bs.entrypoint.file)
        framework = _FRAMEWORK_LABEL.get(bs.entrypoint.framework, bs.entrypoint.framework)
        call_name = (
            "configureSupervisor()"
            if bs.entrypoint.language == "ts"
            else "configure_supervisor()"
        )
        # Generic framework label = "your app" — read more naturally without
        # the leading definite article.
        if bs.entrypoint.framework == "generic":
            anchor = f"near your app's entry point at `{ep_rel}:{bs.entrypoint.line}`"
        else:
            anchor = f"near the {framework} entry point at `{ep_rel}:{bs.entrypoint.line}`"
        out.append(f"`{call_name}` is already called {anchor} — no extra wiring needed.")
    else:
        out.append("")
        ep_rel = _short_path(bs.entrypoint.file)
        framework = _FRAMEWORK_LABEL.get(bs.entrypoint.framework, bs.entrypoint.framework)
        if bs.entrypoint.framework == "generic":
            anchor = f"near your app's entry point at `{ep_rel}:{bs.entrypoint.line}`"
        else:
            anchor = f"near the {framework} entry point at `{ep_rel}:{bs.entrypoint.line}`"
        out.append(f"Then call `configure_supervisor()` once at startup, {anchor}:")
        out.append("")
        if bs.entrypoint.language == "ts":
            out.append("```ts")
            out.append('import { configureSupervisor } from "@runtime-supervisor/guards";')
            out.append("")
            out.append("configureSupervisor();  // reads SUPERVISOR_* env vars")
            out.append("```")
        else:
            out.append("```python")
            out.append("from supervisor_guards import configure_supervisor")
            out.append("")
            out.append("configure_supervisor()  # reads SUPERVISOR_* env vars")
            out.append("```")

    out.append("")
    out.append(
        "Env vars to set (template in `runtime-supervisor/.env.example`):"
    )
    out.append("")
    out.append("- `SUPERVISOR_BASE_URL`")
    out.append("- `SUPERVISOR_APP_ID`")
    out.append("- `SUPERVISOR_SECRET`")
    out.append("")
    out.append(
        "_Without these, every guard runs inert — calls pass through._"
    )
    out.append("")
    return out


def render_start_here_md(sh: StartHere) -> str:
    """Markdown for runtime-supervisor/START_HERE.md.

    Section order is mandatory (see docs/SCAN_COMMUNICATION_RULES.md):
      0. Step 0 — install the SDK (only when `bootstrap` is set)
      1. Best place to wrap first
      2. What this repo can already do
      3. Agent frameworks detected (only when `framework_signals` is set)
      4. Highest-risk things to care about now
      5. Do this now
      6. Ignore this for now
    """
    parts: list[str] = ["# Start here", ""]

    # Framework banner — `langchain`, `llamaindex`, `crewai` source repos hit
    # this. Without it, the user reads the report as if their app were the
    # one with the chokepoints, and ends up wrapping classes the framework
    # marks `@deprecated`. The banner reframes the findings as integration
    # surfaces consumers wrap, not call-sites the maintainer guards.
    if sh.repo_kind == "framework":
        parts.append(
            "> **This is a framework / SDK, not a deployed agent.** "
            "The chokepoints below are *consumer integration surfaces* — "
            "where downstream apps that import this library should drop "
            "their `@supervised` wrap. The framework itself doesn't run an "
            "agent loop here, so don't add the wrap to this repo."
        )
        parts.append("")

    # 0. Step 0 — install the SDK (only when bootstrap was detected)
    parts.extend(_render_step0(sh))

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
    elif sh.framework_signals:
        sig = sh.framework_signals[0]
        rel = _short_path(sig.file)
        parts.append(
            f"We didn't find an agent class or tool registration to point at "
            f"directly. The agent loop runs through `{sig.framework}` "
            f"(`{rel}:{sig.line}`)."
        )
        parts.append("")
        parts.append(
            "Wrap the tool callables passed in (e.g. functions inside "
            "`Tool(func=…)`) or the function that calls `agent.run(...)` / "
            "`AgentExecutor.invoke(...)` — not the import line itself. See "
            "_Agent frameworks detected_ below for every framework hit."
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

    # 2b. agent frameworks detected (only when present)
    if sh.framework_signals:
        parts.append("## Agent frameworks detected")
        parts.append("")
        for sig in sh.framework_signals:
            rel = _short_path(sig.file)
            parts.append(f"- **{sig.framework}** — `{rel}:{sig.line}`")
            parts.append(
                "  _wrap point isn't this line — wrap the tool callable or the "
                "dispatch method (e.g. `AgentExecutor.invoke`)_"
            )
        parts.append("")
        parts.append(
            "_These tell you which loop to look inside, not where to put the "
            "decorator._"
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

    # Step 0 — surface the install command in one line so the CLI reader
    # knows the wrap snippet won't ImportError on first paste.
    if sh.bootstrap is not None and sh.bootstrap.manager is not None:
        bs = sh.bootstrap
        if bs.configure_already_called:
            out.append(f"Step 0: {bs.manager.install_cmd}  (configure_supervisor() already wired)")
        else:
            out.append(f"Step 0: {bs.manager.install_cmd}")
        out.append("")

    out.append("Best place to wrap first:")
    if sh.top_wrap_targets:
        for i, t in enumerate(sh.top_wrap_targets, 1):
            rel = _short_path(t.file)
            out.append(f"  {i}. {t.label:<28s}  {rel}:{t.line}")
    elif sh.framework_signals:
        sig = sh.framework_signals[0]
        rel = _short_path(sig.file)
        out.append(
            f"  (no class / tool to point at — {sig.framework} loop in {rel}:{sig.line};"
        )
        out.append(
            "   wrap the tool callable or the dispatch method, not the import)"
        )
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
