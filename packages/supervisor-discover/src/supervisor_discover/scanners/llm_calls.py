"""Find LLM invocations (openai / anthropic / langchain / llama_index).

Matches ONLY when the call is on something imported from one of the known
LLM SDKs — tracked via alias map. This rules out false positives on
generic `generate()` / `run()` / `invoke()` in files that happened to
also import anthropic elsewhere.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._imports import build_alias_map, resolve_call_name, root_module
from ._utils import python_files, safe_read, ts_js_files

# Canonical module names the scanner recognizes as LLM SDKs.
_LLM_ROOTS = {"openai", "anthropic", "langchain", "langchain_core", "langchain_community",
              "llama_index", "llama_cpp"}

# Method suffixes that are STRONG signals when called on an LLM module/client.
# We still require the root to be an LLM module — these suffixes alone aren't
# enough (e.g. `obj.run()` in non-LLM code).
_LLM_METHOD_SUFFIXES = (
    ".chat.completions.create", ".completions.create", ".responses.create",
    ".messages.create", ".messages.stream",
    ".complete", ".generate", ".invoke", ".run", ".stream",
    ".Anthropic", ".OpenAI", ".AzureOpenAI",
)


def _is_llm_call(dotted: str) -> bool:
    """High-confidence: call path roots at an LLM SDK AND ends with a
    known model-invocation/client-construction suffix."""
    root = root_module(dotted)
    if root not in _LLM_ROOTS:
        return False
    return any(dotted.endswith(sfx) for sfx in _LLM_METHOD_SUFFIXES)


# Method suffixes that are strong LLM signals even when the call root is a
# local variable (e.g. `client = _anthropic.Anthropic(); client.messages.create(...)`).
# Medium-confidence because we can't statically resolve the variable back to
# its constructor, but the method shape is vendor-specific.
_VENDOR_SPECIFIC_METHODS = (
    ".chat.completions.create",
    ".messages.create",
    ".messages.stream",
    ".responses.create",
)


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        aliases = build_alias_map(tree)
        # Fast exit: if the file imports none of the LLM SDKs, skip it.
        if not any(root_module(v) in _LLM_ROOTS for v in aliases.values()):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = resolve_call_name(node, aliases)
            if _is_llm_call(dotted):
                findings.append(Finding(
                    scanner="llm-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=dotted + "(...)",
                    suggested_action_type="tool_use",
                    confidence="high",
                    rationale=f"LLM SDK call `{dotted}`. Gate with @supervised('tool_use') so the "
                              "supervisor's threat pipeline can catch prompt-injection / PII / jailbreak "
                              "in whatever user input flows into the prompt.",
                    extra={"method": dotted, "sdk": root_module(dotted)},
                ))
            elif any(dotted.endswith(sfx) for sfx in _VENDOR_SPECIFIC_METHODS):
                # e.g., `client.messages.create(...)` where `client` was assigned
                # from `_anthropic.Anthropic()`. We can't resolve the variable
                # statically, but the method signature is vendor-specific and
                # the file already imports an LLM SDK (checked above).
                findings.append(Finding(
                    scanner="llm-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=dotted + "(...)",
                    suggested_action_type="tool_use",
                    confidence="medium",
                    rationale=f"Vendor-specific LLM method `{dotted}` in a file that imports an LLM SDK. "
                              "Likely a client invocation — gate with @supervised('tool_use').",
                    extra={"method": dotted, "sdk_in_file": True},
                ))
    return findings


_TS_IMPORT_RE = re.compile(r"""from\s+['"](openai|@anthropic-ai/sdk|langchain|llamaindex|@langchain/[^'"]+)['"]""")
_TS_CALL_RE = re.compile(r"""\b(?:chat\.completions\.create|messages\.(?:create|stream)|responses\.create)\s*\(""")


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
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
                rationale="LLM SDK call — gate with supervised('tool_use').",
                extra={},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
