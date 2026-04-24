"""Detect MCP (Model Context Protocol) tool registrations.

An MCP server exposes a set of tools that an LLM client (Claude Desktop,
Claude Code, Cursor, Continue, …) can invoke. Each tool registration is
the exact surface a malicious prompt can reach. Wrapping the dispatcher
(the `CallToolRequestSchema` handler) gates every tool with one decorator;
wrapping individual tool functions is the per-tool fallback.

What this scanner detects:

  TypeScript / JavaScript:
    - `server.setRequestHandler(CallToolRequestSchema, ...)`   ← dispatcher
    - `server.setRequestHandler(ListToolsRequestSchema, ...)`  ← tool list
    - `server.tool('name', ...)` / `server.registerTool('name', ...)`
    - `new Server(...)` / `new McpServer(...)` from @modelcontextprotocol/sdk
    - imports from @modelcontextprotocol/sdk

  Python:
    - `from mcp.server.fastmcp import FastMCP`
    - `from mcp.server import Server`
    - `@mcp.tool()` / `@app.tool()` / `@server.tool()` decorators
    - `mcp = FastMCP(...)` / `server = Server(...)`

Why MCP gets its own scanner instead of inheriting from agent-orchestrators:
the SDK and patterns are distinct enough that a generic class-name match
would miss them; meanwhile every MCP tool is structurally a chokepoint
worth gating, so they deserve a tier slot of their own (real_world_actions).
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files

# --- TypeScript / JavaScript ---

# Imports from the MCP SDK — informational; we use them to qualify other
# matches as MCP-context.
_TS_IMPORT_MCP = re.compile(
    r"""(?:from|require)\s*\(?['"]@modelcontextprotocol/sdk[^'"]*['"]"""
)

# The catch-all tool dispatcher: every CallTool request lands here.
# Wrapping THIS one handler gates every tool the server exposes.
_TS_DISPATCHER = re.compile(
    r"""\.setRequestHandler\s*\(\s*CallToolRequestSchema\b"""
)

# ListToolsRequestSchema handler — the tool catalog. Less critical than
# the dispatcher, but informative because it tells you what tools exist.
_TS_LIST_TOOLS = re.compile(
    r"""\.setRequestHandler\s*\(\s*ListToolsRequestSchema\b"""
)

# Per-tool registration: server.tool('name', ...) / server.registerTool('name', ...)
_TS_TOOL_DECL = re.compile(
    r"""\.(?:tool|registerTool)\s*\(\s*['"]([\w\-.:]+)['"]"""
)

# Server construction: `new Server({...})` or `new McpServer({...})` —
# only counts as an MCP signal if the file also imports from the SDK.
_TS_SERVER_NEW = re.compile(
    r"""\bnew\s+(?:Mcp)?Server\s*\("""
)

# --- Python ---

_PY_IMPORT_FASTMCP = re.compile(
    r"""\bfrom\s+mcp\.server\.fastmcp\s+import\s+(?:FastMCP|[\w,\s]*\bFastMCP\b)"""
)
_PY_IMPORT_SERVER = re.compile(
    r"""\bfrom\s+mcp\.server\b(?:\.\w+)?\s+import\s+[\w,\s]*\bServer\b"""
)

# `mcp = FastMCP("name")` / `server = Server(...)` — the instance the tools attach to.
_PY_INSTANCE = re.compile(
    r"""^\s*(\w+)\s*=\s*(?:FastMCP|Server)\s*\(""", re.MULTILINE
)

# `@mcp.tool()` / `@app.tool()` / `@mcp.tool(name="…")` — every decorated
# function is one tool the LLM can call.
_PY_TOOL_DECORATOR = re.compile(
    r"""^\s*@(\w+)\.tool\s*\(\s*(?:name\s*=\s*['"]([\w\-.:]+)['"])?""",
    re.MULTILINE,
)


_RATIONALE_DISPATCHER = (
    "MCP CallTool dispatcher — every tool the LLM client invokes flows through "
    "this single handler. Wrapping it with `@supervised('tool_use')` gates ALL "
    "tools at once; the supervisor sees the tool name + args before the handler "
    "runs and can deny / review based on policy. This is the highest-leverage "
    "single wrap for any MCP server."
)

_RATIONALE_TOOL = (
    "MCP tool registration — this name is exposed to the LLM client and can be "
    "invoked by any agent connected to your server. Each tool needs its args "
    "validated and gated; the policy engine catches arg-injection, scope "
    "violations, and rate spikes before the tool runs."
)

_RATIONALE_LIST = (
    "MCP tool catalog handler. Informational — tells the LLM which tools exist. "
    "Not a chokepoint by itself, but useful to enumerate the agent's surface. "
    "If a tool appears here but has no @supervised wrap on its handler, it's "
    "ungated."
)

_RATIONALE_INSTANCE = (
    "MCP server instance. The instance the tools attach to via `@server.tool()` "
    "or `server.setRequestHandler(...)`. Identify the dispatcher and per-tool "
    "registrations on this instance and gate them."
)


def _ts_scan(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    has_import = bool(_TS_IMPORT_MCP.search(text))
    if not has_import:
        # No MCP SDK import on this file — none of the per-tool / dispatcher
        # matches below should fire (they could match Slack SDK or similar).
        return findings

    for m in _TS_DISPATCHER.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            confidence="high",
            rationale=_RATIONALE_DISPATCHER,
            extra={"kind": "mcp-dispatcher", "framework": "mcp"},
        ))

    for m in _TS_LIST_TOOLS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            confidence="medium",
            rationale=_RATIONALE_LIST,
            extra={"kind": "mcp-list-tools", "framework": "mcp"},
        ))

    for m in _TS_TOOL_DECL.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            confidence="high",
            rationale=_RATIONALE_TOOL,
            extra={"kind": "mcp-tool", "framework": "mcp", "tool_name": m.group(1)},
        ))

    for m in _TS_SERVER_NEW.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0)[:80],
            suggested_action_type="tool_use",
            confidence="medium",
            rationale=_RATIONALE_INSTANCE,
            extra={"kind": "mcp-server-instance", "framework": "mcp"},
        ))

    return findings


def _py_scan(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    has_import = bool(_PY_IMPORT_FASTMCP.search(text)) or bool(_PY_IMPORT_SERVER.search(text))
    if not has_import:
        return findings

    instance_names: set[str] = set()
    for m in _PY_INSTANCE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        instance_names.add(m.group(1))
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0).strip()[:80],
            suggested_action_type="tool_use",
            confidence="medium",
            rationale=_RATIONALE_INSTANCE,
            extra={"kind": "mcp-server-instance", "framework": "mcp",
                   "instance_name": m.group(1)},
        ))

    for m in _PY_TOOL_DECORATOR.finditer(text):
        line = text[: m.start()].count("\n") + 1
        instance = m.group(1)
        # If we know the MCP instance names in this file, only count decorators
        # that hang off one of them. This avoids matching unrelated `@x.tool()`
        # calls in other libs that happen to use the same shape.
        if instance_names and instance not in instance_names:
            continue
        findings.append(Finding(
            scanner="mcp-tools",
            file=str(path),
            line=line,
            snippet=m.group(0).strip()[:80],
            suggested_action_type="tool_use",
            confidence="high",
            rationale=_RATIONALE_TOOL,
            extra={"kind": "mcp-tool", "framework": "mcp",
                   "instance_name": instance, "tool_name": m.group(2) or "?"},
        ))

    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_ts_scan(path, text))
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_py_scan(path, text))
    return findings
