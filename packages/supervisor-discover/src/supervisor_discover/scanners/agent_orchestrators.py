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

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

# Paths that strongly imply "this file is agent orchestration, not generic MVC".
_AGENT_PATH_HINTS = (
    "/orchestrator/", "/tool-dispatcher/", "/tool_dispatcher/",
    "/agents/", "/agent/", "/planner/",
    "/controllers/agents/", "/tool-registry/", "/tool_registry/",
)


def _in_agent_path(file: str) -> bool:
    lower = file.lower()
    return any(hint in lower for hint in _AGENT_PATH_HINTS)


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

_CLASS_DEF: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"\bclass\s+(\w*{_AGENT_CLASS_NAMES})\b"), "agent-shaped class name"),
    # TS/JS: `export class Foo` / `export default class Foo`
    (re.compile(rf"\bexport\s+(?:default\s+)?class\s+(\w*{_AGENT_CLASS_NAMES})\b"), "agent-shaped class name"),
]

# LOW-confidence by itself, MEDIUM when in agent path — method defs.
_AGENT_METHOD_NAMES = (
    "handle", "execute", "dispatch", "plan", "reason", "decide",
    "process_intent", "processIntent", "route", "orchestrate",
)
_METHOD_DEFS = re.compile(
    rf"\b(?:async\s+)?(?:def|function)?\s*({'|'.join(_AGENT_METHOD_NAMES)})\s*\("
)

_RATIONALE_CHOKEPOINT = (
    "🎯 AGENT CHOKEPOINT: este es un punto donde fluye toda decisión del agente "
    "(una `Controller.handle()` o `Dispatcher.dispatch()` que despacha a N tools). "
    "Wrappear AQUÍ con `@supervised('tool_use')` te da cobertura de TODOS los tools "
    "— actuales y futuros — con una sola línea. Es la forma de más alto apalancamiento "
    "de gatear un agente."
)

_RATIONALE_REGISTRATION = (
    "Tool registration en agent dispatcher. El nombre del tool te dice qué acción "
    "expone el agente. Protegé idealmente el dispatcher completo (cobertura total); "
    "subsidiariamente, cada tool individualmente."
)

_RATIONALE_FRAMEWORK = (
    "Import de framework de agentes (langchain / langgraph / autogen / crewai / mastra). "
    "El `AgentExecutor` / `Graph` / `Crew` de estos frameworks tiene un entry-point único "
    "que orquesta LLM + tools — wrappear ese entry-point gatea el agente completo."
)


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

    # 3. Agent-shaped class definitions — HIGH in agent paths, MEDIUM otherwise
    for pattern, label in _CLASS_DEF:
        for m in pattern.finditer(text):
            line = text[: m.start()].count("\n") + 1
            class_name = m.group(1) if m.groups() else "?"
            confidence = "high" if in_agent_path else "medium"
            findings.append(Finding(
                scanner="agent-orchestrators",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80],
                suggested_action_type="tool_use",
                confidence=confidence,
                rationale=_RATIONALE_CHOKEPOINT,
                extra={"kind": "agent-class", "class_name": class_name, "pattern": label},
            ))

    # 4. Agent-method definitions — only flag when in agent path, MEDIUM
    if in_agent_path:
        for m in _METHOD_DEFS.finditer(text):
            method_name = m.group(1)
            # Dedup: don't emit a method hit on a file that already got a class hit
            # at approximately the same location (within 10 lines).
            line = text[: m.start()].count("\n") + 1
            if any(
                f.scanner == "agent-orchestrators"
                and f.file == str(path)
                and abs(f.line - line) < 10
                and f.extra.get("kind") == "agent-class"
                for f in findings
            ):
                continue
            findings.append(Finding(
                scanner="agent-orchestrators",
                file=str(path),
                line=line,
                snippet=m.group(0)[:80],
                suggested_action_type="tool_use",
                confidence="medium",
                rationale=_RATIONALE_CHOKEPOINT,
                extra={"kind": "agent-method", "method_name": method_name},
            ))

    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in list(python_files(root)) + list(ts_js_files(root)):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_text(path, text))
    return findings
