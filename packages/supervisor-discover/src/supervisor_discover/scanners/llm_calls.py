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
from ._utils import parse_python, python_files, safe_read, ts_js_files

# Canonical module names the scanner recognizes as LLM SDKs.
_LLM_ROOTS = {"openai", "anthropic", "langchain", "langchain_core", "langchain_community",
              "llama_index", "llama_cpp"}

# Suffixes that mean "the LLM is being called RIGHT HERE" — there's a prompt
# in the args, the model produces output, and any user-controlled text is
# already in flight. These are real chokepoints; rate `high`.
_LLM_INVOCATION_SUFFIXES = (
    ".chat.completions.create", ".completions.create", ".responses.create",
    ".messages.create", ".messages.stream",
    ".complete", ".generate", ".invoke", ".run", ".stream",
)

# Suffixes that mean "an LLM client object is being constructed" — no prompt
# has been issued yet. Wrapping `openai.OpenAI(api_key=...)` does nothing for
# prompt injection; the actual call is `client.chat.completions.create(...)`
# elsewhere. Rate `low` so the constructor surfaces in FULL_REPORT but
# doesn't pollute the public scan's high-confidence top.
_LLM_CONSTRUCTOR_SUFFIXES = (
    ".Anthropic", ".OpenAI", ".AzureOpenAI",
)


def _classify_llm_call(dotted: str) -> str | None:
    """Return "invocation" / "construction" / None.

    Requires the call's root to be in `_LLM_ROOTS` so generic `obj.run()` in
    non-LLM code doesn't fire. The two suffix groups are disjoint by design:
    `chat.completions.create` is always a method call, `.OpenAI` is always a
    class constructor — picking one or the other tells the caller which
    confidence tier to emit.
    """
    root = root_module(dotted)
    if root not in _LLM_ROOTS:
        return None
    if any(dotted.endswith(sfx) for sfx in _LLM_INVOCATION_SUFFIXES):
        return "invocation"
    if any(dotted.endswith(sfx) for sfx in _LLM_CONSTRUCTOR_SUFFIXES):
        return "construction"
    return None


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
        tree = parse_python(text)
        if tree is None:
            continue
        aliases = build_alias_map(tree)
        # Fast exit: if the file imports none of the LLM SDKs, skip it.
        if not any(root_module(v) in _LLM_ROOTS for v in aliases.values()):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = resolve_call_name(node, aliases)
            kind = _classify_llm_call(dotted)
            if kind == "invocation":
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
                    extra={"method": dotted, "sdk": root_module(dotted), "kind": "invocation"},
                ))
            elif kind == "construction":
                findings.append(Finding(
                    scanner="llm-calls",
                    file=str(path),
                    line=node.lineno,
                    snippet=dotted + "(...)",
                    suggested_action_type="tool_use",
                    confidence="low",
                    rationale=f"LLM client constructed at `{dotted}` — no prompt has been issued yet. "
                              "The actual chokepoint is the method that calls `.create(...)` / `.invoke(...)` "
                              "on this client. Track this as an informational signal; gate the call-site, not "
                              "the constructor.",
                    extra={"method": dotted, "sdk": root_module(dotted), "kind": "construction"},
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


# LLM SDK packages the scanner recognizes via TS/JS imports. Three groups:
#   - first-party SDKs: openai, @anthropic-ai/sdk, @anthropic-ai/vertex-sdk
#   - meta-SDKs: ai (Vercel), @ai-sdk/* (Vercel provider packages),
#                langchain, llamaindex, @langchain/*
#   - other vendors: Google GenAI / Vertex, Groq, Cohere, Bedrock, Mistral,
#                    Together, Replicate
#
# Why these matter: voicebox / multica / many trending repos use Vercel AI
# SDK or Google GenAI — neither was covered by the original regex, so they
# scored 0 LLM findings even though they're agent apps.
_TS_IMPORT_RE = re.compile(
    r"""from\s+['"]("""
    r"openai|@anthropic-ai/sdk|@anthropic-ai/vertex-sdk|"
    r"ai|@ai-sdk/[^'\"]+|"
    r"langchain|llamaindex|@langchain/[^'\"]+|@llamaindex/[^'\"]+|"
    r"@google/generative-ai|@google-cloud/vertexai|"
    r"groq-sdk|cohere-ai|@cohere/[^'\"]+|"
    r"@aws-sdk/client-bedrock-runtime|"
    r"mistralai|@mistralai/[^'\"]+|"
    r"together-ai|replicate"
    r""")['"]"""
)

# Method patterns that almost always mean "I'm calling the LLM right now".
# Includes Vercel AI SDK functions (generateText / streamText / generateObject /
# embed), Google GenAI (generateContent), Cohere/Mistral (complete), and
# langchain TS (.invoke).
_TS_CALL_RE = re.compile(
    r"\b(?:"
    r"chat\.completions\.create|"
    r"messages\.(?:create|stream)|"
    r"responses\.create|"
    r"generateText|streamText|"
    r"generateObject|streamObject|"
    r"embed|embedMany|"
    r"generateContent|generateContentStream|"
    r"complete|"
    r"invoke"
    r")\s*\("
)

# `new OpenAI()` / `new Anthropic()` / `new ChatOpenAI()` and friends —
# constructing an LLM client is itself a high-value signal even when no
# `.create()` is called in the same file (the client is often passed to
# another module). The wrapping module is the call-site to gate.
_TS_CONSTRUCT_RE = re.compile(
    r"\bnew\s+(OpenAI|Anthropic|ChatOpenAI|ChatAnthropic|AzureOpenAI|"
    r"VertexAI|GoogleGenerativeAI|GroqClient|Groq|CohereClient|Cohere|"
    r"Mistral|TogetherAI|Replicate|BedrockRuntime|BedrockRuntimeClient)\s*\("
)


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        if not _TS_IMPORT_RE.search(text):
            continue
        seen_lines: set[int] = set()
        for m in _TS_CALL_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                scanner="llm-calls",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type="tool_use",
                confidence="high",
                rationale=(
                    "LLM call — whatever user input flows into the prompt "
                    "or args is reaching the model. Wrap with supervised("
                    "'tool_use') so the supervisor catches prompt injection, "
                    "PII leakage, and runaway loops before the call lands."
                ),
                extra={"kind": "method-call"},
            ))
            seen_lines.add(line)
        for m in _TS_CONSTRUCT_RE.finditer(text):
            line = text[: m.start()].count("\n") + 1
            if line in seen_lines:
                continue  # already reported via method-call regex
            findings.append(Finding(
                scanner="llm-calls",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type="tool_use",
                # `new OpenAI(...)` carries no prompt — wrapping the
                # constructor doesn't gate the model call. Rate `low`
                # so it stays an informational signal; the actual
                # chokepoint is the call-site that uses this client.
                confidence="low",
                rationale=(
                    "LLM client construction — no prompt has been issued yet. "
                    "The chokepoint is the function that calls `.create(...)` / "
                    "`generateText(...)` on this client. Treat as an "
                    "informational signal; gate the call-site, not the constructor."
                ),
                extra={"kind": "construction", "client": m.group(1)},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
