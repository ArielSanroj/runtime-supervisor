"""Detect agent orchestration chokepoints — where EVERY agent action flows through.

This scanner closes a major blind spot: repos with clean architecture (custom
`Controller` / `Dispatcher` / `Orchestrator` classes that wrap LLM + tool calls)
were showing 0 findings because their LLM and payment SDKs are abstracted
behind internal modules. The surface is still agentic — just not surface-able
by SDK-name matching.

What a chokepoint is, and why it matters:
- A single `Controller.handle()` / `Dispatcher.dispatch()` / `ToolRegistry.invoke()`
  is the one point every agent decision passes through on its way to a tool.
- One `@supervised` wrap at that chokepoint gives you coverage for ALL current
  tools + any tool added later, with zero per-tool maintenance.
- The alternative — wrapping every leaf call-site — misses the ones that the
  SDK-based scanners don't recognize (custom payment clients, wrapped LLM
  clients, internal APIs).

What this scanner detects:

  HIGH confidence:
    - Tool registrations: `dispatcher.register("pay_order", ...)`,
      `tool_registry.register(...)`, `.registerTool(...)`, `.addTool(...)`.
    - Imports from known agent frameworks: langchain AgentExecutor / ReAct,
      langgraph, autogen, crewai, mastra.
    - Class defs in `orchestrator/` / `tool-dispatcher/` / `agents/` paths.

  MEDIUM confidence:
    - Class names matching `Controller`, `Dispatcher`, `Orchestrator`, `Planner`,
      `Agent`, `ToolDispatcher` outside those paths.
    - Methods `handle`, `execute`, `dispatch`, `plan`, `reason`, `decide`,
      `process_intent`, `route`, `orchestrate` when inside agent-y class.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import parse_python, python_files, safe_read, ts_js_files

# Paths that strongly imply "this file is agent orchestration, not generic MVC".
_AGENT_PATH_HINTS = (
    "/orchestrator/", "/tool-dispatcher/", "/tool_dispatcher/",
    "/agents/", "/agent/", "/planner/",
    "/controllers/agents/", "/tool-registry/", "/tool_registry/",
)

# Paths that should NEVER be flagged as orchestrators even if they pattern-match.
# These are tests, IDE webviews, build outputs — they may have agent-shaped class
# names or method names but they don't run real agent code in production.
_PATH_EXCLUDES = (
    "/webview/", "/webviews/",                 # VS Code / Electron UI scripts
    "/__tests__/", "/tests/", "/test/",        # test trees (any depth)
    "/e2e/", "/spec/", "/specs/", "/__mocks__/",
    "/node_modules/", "/dist/", "/build/", "/.next/", "/out/",
    "/coverage/", "/htmlcov/",
    "/examples/", "/example/", "/demo/", "/demos/", "/fixtures/",
)
_FILENAME_EXCLUDES = (
    ".test.", ".spec.", ".stories.",
    "_test.py", "_spec.py", "_tests.py",
)


def _in_agent_path(file: str) -> bool:
    lower = file.lower()
    return any(hint in lower for hint in _AGENT_PATH_HINTS)


def _is_excluded_path(file: str) -> bool:
    """True if this path should be skipped — tests, webviews, build output, etc."""
    # Normalize: lowercase + backslash→slash + ensure leading slash so segments
    # like "node_modules/..." at the path root match the "/node_modules/" hint.
    lower = "/" + file.lower().replace("\\", "/").lstrip("/")
    if any(seg in lower for seg in _PATH_EXCLUDES):
        return True
    name = lower.rsplit("/", 1)[-1]
    return any(tok in name for tok in _FILENAME_EXCLUDES)


# HIGH-confidence — direct evidence of tool registration.
_TOOL_REGISTRY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:dispatcher|tool_registry|tools|registry)\.register\s*\(\s*['\"]([\w\-.:]+)['\"]"),
     "tool registered in dispatcher"),
    (re.compile(r"\.registerTool\s*\(\s*(?:['\"]([\w\-.:]+)['\"]|{[\s\S]*?name\s*:\s*['\"]([\w\-.:]+)['\"])"),
     "tool registered via registerTool()"),
    (re.compile(r"\.addTool\s*\(\s*(?:['\"]([\w\-.:]+)['\"]|{[\s\S]*?name\s*:\s*['\"]([\w\-.:]+)['\"])"),
     "tool registered via addTool()"),
    (re.compile(r"\btools\s*:\s*\[[\s\S]{0,500}?\b(?:tool|Tool)\b", re.MULTILINE),
     "tools array on agent construction"),
]

# HIGH-confidence — agent-framework imports.
_FRAMEWORK_IMPORTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"from\s+langchain[\w.]*\s+import\s+[\w\s,]*\b(?:AgentExecutor|Agent|ReActAgent|create_react_agent|create_openai_tools_agent|initialize_agent)\b"),
     "langchain"),
    (re.compile(r"from\s+langgraph[\w.]*\s+import\s+[\w\s,]*\b(?:StateGraph|Graph|create_react_agent)\b"),
     "langgraph"),
    (re.compile(r"from\s+autogen[\w.]*\s+import\s+[\w\s,]*\b(?:ConversableAgent|AssistantAgent|UserProxyAgent|GroupChat)\b"),
     "autogen"),
    (re.compile(r"from\s+crewai[\w.]*\s+import\s+[\w\s,]*\b(?:Agent|Crew|Task)\b"),
     "crewai"),
    (re.compile(r"import\s+.*\bfrom\s+['\"]@mastra/core['\"]"), "mastra"),
    (re.compile(r"\bnew\s+(AgentExecutor|Agent|ChatAgent|ReActAgent)\s*\("), "langchain.js / custom agent"),
    # Python-side alt syntax
    (re.compile(r"\bAgentExecutor\s*\(|\binitialize_agent\s*\("), "langchain python"),
]

# MEDIUM-confidence — class defs with agent-y names.
_AGENT_CLASS_NAMES = r"(?:Controller|Dispatcher|Orchestrator|Planner|Agent|ToolDispatcher|AgentExecutor|AgentRouter)"

# Shims / test doubles / abstract bases — names that look agent-shaped but
# never run a real agent in prod. Filter OUT matches whose class name
# contains any of these tokens (case-insensitive).
_CLASS_NAME_BLOCKLIST = (
    "stub", "mock", "fake", "dummy", "compat", "shim",
    "base", "abstract", "proto", "test",
)

_CLASS_DEF: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"\bclass\s+(\w*{_AGENT_CLASS_NAMES})\b"), "agent-shaped class name"),
    # TS/JS: `export class Foo` / `export default class Foo`
    (re.compile(rf"\bexport\s+(?:default\s+)?class\s+(\w*{_AGENT_CLASS_NAMES})\b"), "agent-shaped class name"),
]


def _is_shim_class(name: str) -> bool:
    lower = name.lower()
    return any(tok in lower for tok in _CLASS_NAME_BLOCKLIST)

# LOW-confidence by itself, MEDIUM when in agent path — method defs.
_AGENT_METHOD_NAMES = (
    "handle", "execute", "dispatch", "plan", "reason", "decide",
    "process_intent", "processIntent", "route", "orchestrate",
)
_AGENT_METHOD_NAMES_SET = frozenset(_AGENT_METHOD_NAMES)
# JS/TS: no cheap AST available, stay on regex — but require the `function`
# keyword so matches can't leak into comments or call sites. (Python uses
# AST — see `_py_method_defs` below.)
_METHOD_DEFS_JS = re.compile(
    rf"\b(?:async\s+)?function\s+({'|'.join(_AGENT_METHOD_NAMES)})\s*\("
)

_RATIONALE_CHOKEPOINT = (
    "🎯 AGENT CHOKEPOINT: a single point every agent decision flows through "
    "(a `Controller.handle()` or `Dispatcher.dispatch()` that dispatches to N tools). "
    "Wrapping HERE with `@supervised('tool_use')` covers ALL tools — present and future — "
    "with one line. Highest-leverage way to gate an agent."
)

_RATIONALE_REGISTRATION = (
    "Tool registration in an agent dispatcher. The tool name tells you what action "
    "the agent exposes. Ideally protect the full dispatcher (total coverage); "
    "as a fallback, wrap each tool individually."
)

_RATIONALE_FRAMEWORK = (
    "Import of an agent framework (langchain / langgraph / autogen / crewai / mastra). "
    "The `AgentExecutor` / `Graph` / `Crew` from these frameworks has a single entry-point "
    "that orchestrates LLM + tools — wrapping that entry-point gates the entire agent."
)

# Custom in-house orchestrators: a file in an `orchestrator/`-shaped directory
# (or named `orchestrator.{ts,py}` / `dispatcher.{ts,py}` / `router.{ts,py}`)
# that contains intent-based dispatch — even when no LangChain / LangGraph
# import is present. Targets the A2A pattern in repos like the GiftedAgentV2
# Supabase edge function: `registry.register({intents: [...]})` + an entry
# function that calls `registry.execute(agent, {intent, params})`.
#
# We check path + content together — path alone is too noisy (a `/router/`
# dir might be an HTTP router with no agent dispatch), content alone fires
# on generic switch statements anywhere.
_CUSTOM_ORCH_DIR_HINTS = (
    "/orchestrator/", "/orchestrators/",
    "/dispatcher/", "/dispatchers/",
    "/agent-router/", "/agent_router/", "/intent-router/", "/intent_router/",
    "/coordinator/", "/coordinators/",
)
_CUSTOM_ORCH_FILENAMES = (
    "orchestrator.ts", "orchestrator.tsx", "orchestrator.py",
    "dispatcher.ts", "dispatcher.tsx", "dispatcher.py",
    "router.ts", "router.tsx", "router.py",
    "coordinator.ts", "coordinator.py",
)

_CUSTOM_ORCH_DISPATCH_PATTERNS: list[re.Pattern] = [
    # A2A registry pattern: `registry.register({ name: "X", intents: [...] })`.
    # The existing _TOOL_REGISTRY_PATTERNS only catches the string-arg form;
    # this variant takes an object literal so it slipped through.
    re.compile(r"\bregistry\.register\s*\(\s*\{"),
    # `registry.execute(agent, { intent: ..., params: ... })` — the actual
    # dispatch step. Strongest single signal of "this is the chokepoint".
    re.compile(r"\bregistry\.execute\s*\("),
    # Intent classifier emitting routing decisions.
    re.compile(r"\bintents\.push\s*\(\s*\{"),
    # Imperative dispatch chain.
    re.compile(
        r"\bswitch\s*\(\s*(?:intent|type|action|kind|"
        r"msg\.type|message\.type|input\.type|payload\.kind)\b"
    ),
    # Python-style attribute access on classification result.
    re.compile(r"\bclassif(?:y|ication)\.intents\b"),
    # Object-map registry: `const HANDLERS: Record<string, ...> = { task_create: …, … }`
    re.compile(
        r"\b(?:HANDLERS|AGENTS|ROUTES|INTENT_MAP)\s*[:=][^=]{0,40}\{",
        re.IGNORECASE,
    ),
]

_RATIONALE_CUSTOM_ORCH = (
    "🎯 CUSTOM ORCHESTRATOR: an in-house agent loop. The file routes intents to "
    "sub-agents/handlers without using LangChain or another framework, so the "
    "framework-import detector misses it. Wrap the entry function (often the HTTP "
    "handler that calls `registry.execute(...)` or a `dispatch(intent)` switch) "
    "to gate every agent decision in this app."
)


def _is_custom_orchestrator_file(file: str) -> bool:
    """True when the file looks like an in-house orchestrator dispatch surface
    (matched by directory or filename — actual content is checked separately)."""
    lower = "/" + file.lower().replace("\\", "/").lstrip("/")
    if any(hint in lower for hint in _CUSTOM_ORCH_DIR_HINTS):
        return True
    name = lower.rsplit("/", 1)[-1]
    return name in _CUSTOM_ORCH_FILENAMES


def _custom_orch_findings(path: Path, text: str) -> list[Finding]:
    """Emit at most one chokepoint per orchestrator-shaped file when its
    content actually does intent dispatch. We pick the line of the FIRST
    matching pattern as the anchor — typically `registry.execute(...)`, the
    spot the user actually has to wrap."""
    if not _is_custom_orchestrator_file(str(path)):
        return []
    earliest_line: int | None = None
    earliest_snippet: str = ""
    for pattern in _CUSTOM_ORCH_DISPATCH_PATTERNS:
        m = pattern.search(text)
        if m is None:
            continue
        line = text[: m.start()].count("\n") + 1
        if earliest_line is None or line < earliest_line:
            earliest_line = line
            earliest_snippet = m.group(0)[:80].replace("\n", " ")
    if earliest_line is None:
        return []
    # Class label: parent dir name capitalized + `"Orchestrator"` suffix when
    # it isn't already there. Gives the user a concrete identifier to grep.
    parent = path.parent.name or path.stem
    label = parent[:1].upper() + parent[1:] if parent else "Orchestrator"
    if not label.lower().endswith(("orchestrator", "dispatcher", "router", "coordinator")):
        label = f"{label}Orchestrator"
    return [Finding(
        scanner="agent-orchestrators",
        file=str(path),
        line=earliest_line,
        snippet=earliest_snippet,
        suggested_action_type="tool_use",
        confidence="high",
        rationale=_RATIONALE_CUSTOM_ORCH,
        extra={
            "kind": "agent-class",
            "class_name": label,
            "pattern": "custom-orchestrator",
        },
    )]


def _scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    in_agent_path = _in_agent_path(str(path))

    # 1. Tool registrations — HIGH
    for pattern, label in _TOOL_REGISTRY_PATTERNS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            tool_name = next((g for g in m.groups() if g), "?")
            findings.append(Finding(
                scanner="agent-orchestrators",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80].replace("\n", " "),
                suggested_action_type="tool_use",
                confidence="high",
                rationale=_RATIONALE_REGISTRATION,
                extra={"kind": "tool-registration", "tool_name": tool_name, "pattern": label},
            ))

    # 2. Framework imports — HIGH
    for pattern, framework in _FRAMEWORK_IMPORTS:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                scanner="agent-orchestrators",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80].replace("\n", " "),
                suggested_action_type="tool_use",
                confidence="high",
                rationale=_RATIONALE_FRAMEWORK,
                extra={"kind": "framework-import", "framework": framework},
            ))

    # Pre-compute per-class parallel-dispatch surfaces (Python only). Used to
    # annotate agent-class findings whose class has e.g. 5 distinct
    # `dispatch_*_alert` methods — wrapping the class definition alone is NOT
    # enough, the user has to wrap each method (or refactor through a common
    # helper). Empty for non-Python files.
    multi_method_classes = (
        _multi_method_dispatchers(text) if path.suffix == ".py" else {}
    )

    # 3. Agent-shaped class definitions — HIGH in agent paths, MEDIUM otherwise.
    # Skip shims (Stub/Mock/Fake/Compat/…) — they match the name regex but are
    # test doubles or abstract bases, never the real orchestrator in prod.
    for pattern, label in _CLASS_DEF:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            class_name = m.group(1) if m.groups() else "?"
            if _is_shim_class(class_name):
                continue
            confidence = "high" if in_agent_path else "medium"
            extra: dict[str, object] = {
                "kind": "agent-class",
                "class_name": class_name,
                "pattern": label,
            }
            parallel_methods = multi_method_classes.get(class_name) or []
            if parallel_methods:
                extra["parallel_methods"] = parallel_methods
                extra["multi_method_dispatcher"] = True
            findings.append(Finding(
                scanner="agent-orchestrators",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80],
                suggested_action_type="tool_use",
                confidence=confidence,
                rationale=_RATIONALE_CHOKEPOINT,
                extra=extra,
            ))

    # 4. Agent-method definitions — only flag when in agent path, MEDIUM.
    # Python uses AST (Layer 3 defense: immune to word-matches in comments
    # or strings). JS/TS falls back to regex with required `function` keyword.
    if in_agent_path:
        if path.suffix == ".py":
            findings.extend(_py_method_defs(path, text, findings))
        else:
            findings.extend(_js_method_defs(path, text, findings))

    # 5. Custom in-house orchestrators — fires only when no class match in the
    # same file already gave us a chokepoint (avoid duplicate findings on
    # files that have BOTH `class FooOrchestrator` and intent dispatch).
    has_class_chokepoint = any(
        f.extra.get("kind") == "agent-class" and f.file == str(path)
        for f in findings
    )
    if not has_class_chokepoint:
        findings.extend(_custom_orch_findings(path, text))

    return findings


# Method-name prefixes that indicate "this is one of N parallel dispatch
# entry-points" — wrapping the class alone misses them, because each method
# is the actual public API the caller invokes. The snippet rationale we ship
# downstream changes when we detect ≥2 of these on the same class.
_PARALLEL_DISPATCH_PREFIXES = (
    "dispatch_", "handle_", "send_", "process_", "route_", "on_",
)
# Suffixes paired with the prefixes — `send_email` counts, `send_data` doesn't.
# Empty string = any suffix accepted (used for `dispatch_*`, `handle_*`).
_PARALLEL_DISPATCH_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("dispatch_", ()),                 # any dispatch_*
    ("handle_", ()),                   # any handle_*
    ("route_", ()),                    # any route_*
    ("send_", ("_alert", "_notification", "_message", "_email", "_sms", "_invite")),
    ("process_", ("_event", "_message", "_alert")),
    ("on_", ("_event", "_message")),
)

_DISPATCH_HELPERS = frozenset({
    "dispatch", "handle", "execute", "send", "process", "route",
    "_create_and_dispatch", "_dispatch", "_handle", "_execute",
})


def _is_parallel_dispatch_method(name: str) -> bool:
    """True when `name` looks like one of N peer dispatch methods (e.g.
    `dispatch_sla_alert`, `send_email_invite`). Filters out:
      - private/dunder methods (`_dispatch_to_log`, `__init__`)
      - the catch-all `dispatch`/`handle`/`execute` (those are the *target*
        if a class has them — we don't double-count them as peers).
    """
    if name.startswith("_") or name == "":
        return False
    if name in _DISPATCH_HELPERS:
        return False
    for prefix, suffixes in _PARALLEL_DISPATCH_PATTERNS:
        if not name.startswith(prefix):
            continue
        # `dispatch_` alone (no suffix) was excluded above. Require something
        # after the prefix to count: `dispatch_foo` is parallel, `dispatch` is
        # the catch-all helper.
        rest = name[len(prefix):]
        if not rest:
            continue
        if not suffixes:
            return True
        return any(rest.endswith(suf) for suf in suffixes)
    return False


def _multi_method_dispatchers(text: str) -> dict[str, list[str]]:
    """Map class_name → sorted list of parallel dispatch method names, for
    classes with ≥2 such methods. AST-based — won't mis-count comments or
    docstrings. Public methods only (no leading `_`) so we report exactly the
    surface the user has to wrap one-by-one.

    Returns empty dict when the file isn't valid Python or when no class has
    ≥2 parallel dispatch methods.
    """
    tree = parse_python(text)
    if tree is None:
        return {}
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        names: list[str] = []
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_parallel_dispatch_method(child.name):
                    names.append(child.name)
        if len(names) >= 2:
            out[node.name] = sorted(names)
    return out


def _py_method_defs(path: Path, text: str, existing: list[Finding]) -> list[Finding]:
    """AST-based Python method detection. Immune to word matches in comments,
    docstrings, f-strings, and call sites — the AST only parses real defs."""
    tree = parse_python(text)
    if tree is None:
        return []
    source_lines = text.splitlines()
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in _AGENT_METHOD_NAMES_SET:
            continue
        line = node.lineno
        if _near_class_hit(existing, str(path), line):
            continue
        snippet = source_lines[line - 1].strip()[:80] if line - 1 < len(source_lines) else f"def {node.name}("
        out.append(Finding(
            scanner="agent-orchestrators",
            file=str(path),
            line=line,
            snippet=snippet,
            suggested_action_type="tool_use",
            # HIGH: this branch is only reached when `in_agent_path` was true at
            # the caller, so the path-hint is already strong signal. Same rule
            # as agent-class (see line ~210). Keeps chokepoints visible when
            # the public UI filters to high-confidence only.
            confidence="high",
            rationale=_RATIONALE_CHOKEPOINT,
            extra={"kind": "agent-method", "method_name": node.name},
        ))
    return out


def _js_method_defs(path: Path, text: str, existing: list[Finding]) -> list[Finding]:
    """Regex-based JS/TS method detection. Requires `function` keyword so
    we can't accidentally match a bare method name in a comment or call."""
    out: list[Finding] = []
    for m in _METHOD_DEFS_JS.finditer(text):
        method_name = m.group(1)
        line = text[: m.start()].count("\n") + 1
        if _near_class_hit(existing, str(path), line):
            continue
        out.append(Finding(
            scanner="agent-orchestrators",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            # See comment in _py_method_defs — same rationale.
            confidence="high",
            rationale=_RATIONALE_CHOKEPOINT,
            extra={"kind": "agent-method", "method_name": method_name},
        ))
    return out


def _near_class_hit(existing: list[Finding], path: str, line: int) -> bool:
    """Dedup: don't emit a method hit on a file that already got a class
    hit within 10 lines — the class is the more informative anchor."""
    return any(
        f.scanner == "agent-orchestrators"
        and f.file == path
        and abs(f.line - line) < 10
        and f.extra.get("kind") == "agent-class"
        for f in existing
    )


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        if _is_excluded_path(str(path)):
            continue
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_text(path, text))
    return findings
