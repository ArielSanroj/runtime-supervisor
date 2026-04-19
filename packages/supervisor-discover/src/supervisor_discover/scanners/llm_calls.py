"""Find LLM invocations (openai / anthropic / langchain / llama_index)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, ts_js_files

_PY_IMPORT_HINTS = {"openai", "anthropic", "langchain", "langchain_core", "llama_index", "llama_cpp"}
_PY_METHOD_HINTS = {
    "chat.completions.create", "completions.create", "responses.create",
    "messages.create", "complete", "generate", "invoke", "run", "stream",
    "Anthropic", "OpenAI",
}

_TS_IMPORT_RE = re.compile(r"""from\s+['"](openai|@anthropic-ai/sdk|langchain|llamaindex|@langchain/[^'"]+)['"]""")
_TS_CALL_RE = re.compile(r"""\b(?:chat\.completions\.create|messages\.create|responses\.create|invoke|generate)\s*\(""")


def _has_llm_import_py(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _PY_IMPORT_HINTS:
                    return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] in _PY_IMPORT_HINTS
        ):
            return True
    return False


def _py_call_name(node: ast.Call) -> str:
    fn = node.func
    parts: list[str] = []
    while isinstance(fn, ast.Attribute):
        parts.append(fn.attr)
        fn = fn.value
    if isinstance(fn, ast.Name):
        parts.append(fn.id)
    return ".".join(reversed(parts))


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        if not _has_llm_import_py(tree):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _py_call_name(node)
            if any(hint in name for hint in _PY_METHOD_HINTS):
                findings.append(Finding(
                    scanner="llm-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=name + "(...)",
                    suggested_action_type="tool_use",
                    confidence="high",
                    rationale=f"LLM call `{name}`. The supervisor should gate tool_use for any payload "
                              "that can contain prompt-injection or PII leaks.",
                    extra={"method": name},
                ))
    return findings


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = path.read_text(errors="ignore")
        if not _TS_IMPORT_RE.search(text):
            continue
        for m in _TS_CALL_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                scanner="llm-calls",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type="tool_use",
                confidence="high",
                rationale="LLM SDK call — any payload derived from user input should be guarded.",
                extra={},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
