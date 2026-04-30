"""Intra-procedural taint tracking for LLM-output detection.

Goal: identify Python functions where text returned from an LLM SDK
(`client.messages.create()`, `openai.chat.completions.create()`, etc.)
flows to a user-facing sink (HTTP response, route return, email body)
without passing through a sanitizer (a function that validates the
content against a source-of-truth — `assert_entities_in_scope`,
`lookup_person`, `validate_*`, etc.).

This is the regression target for the Andrea/Prodesa class: the LLM
asserts something false, the user sees the assertion as data. The
existing `llm-calls` detector finds the model call; this module finds
the *path* from that call to the user.

Algorithm (simplified intra-procedural):

  1. For each `FunctionDef` / `AsyncFunctionDef`, build a per-function
     taint map: `var_name -> tainted?`. A var is tainted iff its value
     traces back (transitively, via assignments / attribute access /
     method chains / f-strings / subscripts) to the return value of a
     source call.

  2. Sinks the algorithm recognizes:
       - `return <expr>` where <expr> uses a tainted var
       - calls to known sink functions (`res.send`, `jsonify`, etc.)
         where any argument uses a tainted var

  3. Sanitizers absorb taint: when a tainted var is passed to a function
     whose name matches a sanitizer pattern, the *result* is clean.
     Naming heuristic: `assert_*`, `validate_*`, `check_*`, `verify_*`,
     `filter_*`, `sanitize_*`, `guard_*`, `lookup_*`, `find_*`, `is_in_*`,
     plus the explicit `assert_entities_in_scope` from
     `supervisor_guards.scope` (PR 2's helper).

False positives we tolerate (medium confidence):
  - The dev validated via `if check(reply): return reply` — the var name
    is the same in both branches. Practically rare for chatbots; flagging
    keeps the detector simple.
  - The dev reused a tainted var name for unrelated content downstream.
    The `confidence="medium"` gate keeps these out of the public top.

What v1 does NOT do (deferred to v2):
  - Cross-function taint (only intra-procedural; a tainted return from
    `format_reply(text)` is detected by the `Return` rule but not
    re-tainted in the caller). v1.5 in PR 3 if time permits.
  - Loop-aware taint (a tainted var in a `for` loop's body is treated
    the same as outside).
  - JS / TS — Python only for v1; tree-sitter integration is its own PR.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from ._imports import resolve_call_name, root_module


# Sources: dotted suffixes that mean "the LLM is being invoked here".
# Mirrors `llm_calls._LLM_INVOCATION_SUFFIXES` to keep the two detectors
# in sync; importing the constant directly would create a cycle.
LLM_SOURCE_SUFFIXES = (
    ".chat.completions.create",
    ".completions.create",
    ".responses.create",
    ".messages.create",
    ".messages.stream",
    ".complete",
    ".generate",
    ".invoke",
    ".run",
    ".stream",
)

# The roots that count as LLM-bearing imports. Same set as `llm_calls.py`.
LLM_SOURCE_ROOTS = frozenset({
    "openai", "anthropic",
    "langchain", "langchain_core", "langchain_community",
    "llama_index", "llama_cpp",
})

# Sinks: function-call shapes that put tainted text in front of a user.
# Matched by dotted suffix to be framework-agnostic. Plain `return` is
# handled separately as a structural sink, not a call sink.
SINK_CALL_SUFFIXES = (
    ".jsonify",                 # flask
    ".json_response", ".JSONResponse",
    ".HTMLResponse", ".PlainTextResponse",
    ".send", ".send_json", ".send_message",
    ".write", ".write_response",
    ".render", ".render_template", ".render_template_string",
    ".sendmail", ".send_email", ".send_mail",
    ".send", ".say", ".reply",  # slack/discord-shaped
    ".text_to_speech", ".tts",
)

# Sanitizer patterns. Matched on the bare function/method name (not the
# full dotted path) so module-prefixed vs flat imports both fire. Order
# matters only for readability; the union is what we test against.
_SANITIZER_NAME_PATTERNS = (
    re.compile(r"^assert_\w*"),
    re.compile(r"^validate_?\w*"),
    re.compile(r"^check_\w*"),
    re.compile(r"^verify_\w*"),
    re.compile(r"^filter_\w*"),
    re.compile(r"^sanitize_?\w*"),
    re.compile(r"^guard_\w*"),
    # "lookup / find / fetch" of an entity = the dev cross-referenced the
    # source-of-truth, treat the result as clean. We match these even
    # without the `_entity` suffix because chatbot codebases use the
    # plain forms (`lookup_user`, `find_member`, `fetch_team`).
    re.compile(r"^lookup_?\w*"),
    re.compile(r"^find_?\w*"),
    re.compile(r"^fetch_?\w*"),
    re.compile(r"^get_?(?:person|entity|user|name|member|team|role|account)\w*"),
    re.compile(r"^is_in_(?:team|scope|allowed)\w*"),
    # PR 2's helper — match the bare name plus the dotted form.
    re.compile(r"^assert_entities_in_scope$"),
)


def _is_sanitizer_name(name: str) -> bool:
    bare = name.rsplit(".", 1)[-1]
    return any(p.match(bare) for p in _SANITIZER_NAME_PATTERNS)


@dataclass
class TaintFinding:
    """A function where LLM output flows to a user-facing sink without
    a sanitizer in the path. Position points at the SINK so the user
    sees where to add the guard, not where the LLM is called (the
    llm-calls detector already covers that side)."""

    file: str
    line: int
    snippet: str
    func_name: str
    source_line: int
    sink_kind: str   # "return" | "http_response" | "email" | "messaging" | ...
    confidence: str  # "high" if same FunctionDef, "medium" if cross-function


# ── visitor ─────────────────────────────────────────────────────────


class _FunctionTaintVisitor(ast.NodeVisitor):
    """Walks one FunctionDef and tracks per-name taint. Created fresh
    for each function so taint can't bleed across scopes."""

    def __init__(self, *, aliases: dict[str, str], func: ast.FunctionDef | ast.AsyncFunctionDef,
                 file: str, findings: list[TaintFinding]):
        self.aliases = aliases
        self.func = func
        self.file = file
        self.findings = findings

        # Variable name → line of first taint. The line lets the finding
        # point back at the source if needed; for the actual finding we
        # report the SINK line.
        self.tainted: dict[str, int] = {}
        # Last-seen LLM source line in this function (for `source_line`
        # on findings emitted from a `return` whose only "taint" is a
        # raw expression — though those produce no var to record).
        self.latest_source_line: int = 0

    # ─ helpers ────────────────────────────────────────────────────

    def _resolve_call_dotted(self, call: ast.Call) -> str:
        """Return the dotted name of the call (e.g. `client.messages.create`).
        Uses the alias map only for the import root; for variable-bound
        calls (`client.messages.create`) the local name is preserved."""
        return resolve_call_name(call, self.aliases)

    def _is_llm_source_call(self, call: ast.Call) -> bool:
        dotted = self._resolve_call_dotted(call)
        if not dotted:
            return False
        # The strict check (root in LLM_SOURCE_ROOTS) catches `openai.X` /
        # `anthropic.X` calls. The vendor-method check catches the
        # `client = anthropic.Anthropic(); client.messages.create(...)`
        # pattern where the local var is `client` (not in LLM_SOURCE_ROOTS).
        if root_module(dotted) in LLM_SOURCE_ROOTS:
            return any(dotted.endswith(sfx) for sfx in LLM_SOURCE_SUFFIXES)
        # Vendor-specific suffixes from local-bound clients. Lower bar
        # than the import-rooted check, hence this exists at all.
        VENDOR_METHODS = (".messages.create", ".messages.stream",
                          ".chat.completions.create", ".responses.create")
        return any(dotted.endswith(sfx) for sfx in VENDOR_METHODS)

    def _is_sink_call(self, call: ast.Call) -> tuple[bool, str]:
        """Returns (is_sink, kind). `kind` is "http_response" / "email" /
        "messaging" depending on the suffix, used for the finding's
        `sink_kind` field.

        We try the dotted resolution first (catches `flask.jsonify`,
        `client.send`). For chained calls — `smtplib.SMTP('x').sendmail(...)`
        — `resolve_call_name` returns empty because it can't peel past a
        `Call` in the middle of the chain. Falling back to the bare
        attribute name handles that shape: the last `.sendmail` segment
        is enough signal regardless of what's on its left.
        """
        dotted = self._resolve_call_dotted(call)
        candidates: list[str] = []
        if dotted:
            candidates.append(dotted)
        # Bare last-attr fallback: for `<anything>.sendmail(...)` we'd
        # rather over-detect than miss the email path.
        if isinstance(call.func, ast.Attribute):
            candidates.append("." + call.func.attr)

        for cand in candidates:
            for sfx in SINK_CALL_SUFFIXES:
                if cand.endswith(sfx):
                    if "mail" in sfx.lower():
                        return True, "email"
                    if "say" in sfx or "reply" in sfx or "send_message" in sfx:
                        return True, "messaging"
                    if "tts" in sfx.lower() or "text_to_speech" in sfx:
                        return True, "voice"
                    return True, "http_response"
        return False, ""

    def _expr_uses_tainted(self, node: ast.AST | None) -> bool:
        """True if the expression reads a tainted variable, transitively
        through Attribute / Subscript / BinOp / JoinedStr / Tuple etc."""
        if node is None:
            return False
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
        return False

    # ─ assignment-side taint propagation ──────────────────────────

    def _assign_target_names(self, target: ast.expr) -> list[str]:
        """Pull the bound names out of an assignment target. Handles
        `x = ...`, `x, y = ...`, `[a, b] = ...`. Skips Subscript /
        Attribute because tainting `obj.attr` doesn't help us in v1."""
        names: list[str] = []
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                names.extend(self._assign_target_names(elt))
        return names

    def _rhs_taints(self, rhs: ast.expr | None) -> bool:
        """Decide whether the right-hand side of an assignment produces
        a tainted result. Three rules:
          - any direct LLM source call → tainted
          - sanitizer call ANYWHERE in the RHS → CLEAN even if the args
            were tainted (sanitizer absorbs)
          - else if RHS reads a tainted var → tainted
        """
        if rhs is None:
            return False
        # Sanitizer absorption: walk the RHS for any Call whose dotted
        # name matches a sanitizer pattern. If there's at least one,
        # taint is absorbed for the whole RHS — we trust the dev that
        # the sanitizer is doing its job.
        for sub in ast.walk(rhs):
            if isinstance(sub, ast.Call):
                dotted = self._resolve_call_dotted(sub)
                if dotted and _is_sanitizer_name(dotted):
                    return False

        # Source: an LLM call anywhere in the RHS taints the result.
        for sub in ast.walk(rhs):
            if isinstance(sub, ast.Call) and self._is_llm_source_call(sub):
                self.latest_source_line = sub.lineno
                return True

        # Transitive: the RHS reads a tainted var.
        return self._expr_uses_tainted(rhs)

    # ─ visit ──────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        tainted = self._rhs_taints(node.value)
        for tgt in node.targets:
            names = self._assign_target_names(tgt)
            for n in names:
                if tainted:
                    self.tainted[n] = node.lineno
                else:
                    # Re-assignment to a NON-tainted RHS clears the var.
                    # Keeps `x = sanitize(x)` from leaving x tainted.
                    self.tainted.pop(n, None)
        # Don't generic_visit — we've already walked the RHS via
        # _rhs_taints, and re-walking would double-count source lines.

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # `x += llm_call().text` — RHS taints x just like Assign.
        if isinstance(node.target, ast.Name):
            if self._rhs_taints(node.value):
                self.tainted[node.target.id] = node.lineno

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        # Sanitizer-in-return absorbs taint: `return validate_scope(reply)`.
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Call):
                dotted = self._resolve_call_dotted(sub)
                if dotted and _is_sanitizer_name(dotted):
                    return
        if self._expr_uses_tainted(node.value):
            self.findings.append(TaintFinding(
                file=self.file,
                line=node.lineno,
                snippet=f"return ... (tainted by LLM output, def {self.func.name})",
                func_name=self.func.name,
                source_line=self.latest_source_line,
                sink_kind="return",
                confidence="high",
            ))
        # Direct source-call return without intermediate var — `return
        # client.messages.create(...).content[0].text` — counts too.
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Call) and self._is_llm_source_call(sub):
                # Only emit if no sibling sanitizer was already present
                # (handled by the early return above).
                self.findings.append(TaintFinding(
                    file=self.file,
                    line=node.lineno,
                    snippet=f"return ... (LLM call inline, def {self.func.name})",
                    func_name=self.func.name,
                    source_line=sub.lineno,
                    sink_kind="return",
                    confidence="high",
                ))
                break

    def visit_Call(self, node: ast.Call) -> None:
        is_sink, kind = self._is_sink_call(node)
        if not is_sink:
            self.generic_visit(node)
            return
        # Sanitizer-absorption inside the same call expr: `res.send(filter(reply))`.
        for sub in ast.walk(node):
            if sub is node:
                continue
            if isinstance(sub, ast.Call):
                dotted = self._resolve_call_dotted(sub)
                if dotted and _is_sanitizer_name(dotted):
                    self.generic_visit(node)
                    return
        # Any tainted arg → sink is reached.
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if self._expr_uses_tainted(arg):
                self.findings.append(TaintFinding(
                    file=self.file,
                    line=node.lineno,
                    snippet=f"{ast.unparse(node.func) if hasattr(ast, 'unparse') else 'sink'}(...)",
                    func_name=self.func.name,
                    source_line=self.latest_source_line,
                    sink_kind=kind,
                    confidence="high",
                ))
                break
        self.generic_visit(node)


# ── public entrypoint ───────────────────────────────────────────────


def find_taint(tree: ast.AST, *, aliases: dict[str, str], file: str) -> list[TaintFinding]:
    """Scan a parsed module for LLM-output → user-facing-sink flows
    without intermediate sanitization.

    Returns one `TaintFinding` per (function, sink). The same source
    can produce multiple findings if the LLM output reaches more than
    one sink in the same function (a chatbot logging the reply to email
    AND returning it to the HTTP client, for example)."""
    findings: list[TaintFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Fast exit: if the function body never references an LLM-source
        # API name AND has no sink-name reference, taint can't fire.
        # Lazy approximation — checks substrings only — but the actual
        # visitor still does the full AST verification.
        body_text_hint = " ".join(
            ast.dump(b) for b in node.body
        )
        if "create" not in body_text_hint and "invoke" not in body_text_hint and "complete" not in body_text_hint:
            continue
        visitor = _FunctionTaintVisitor(
            aliases=aliases, func=node, file=file, findings=findings,
        )
        for stmt in node.body:
            visitor.visit(stmt)
    return findings


__all__ = [
    "find_taint",
    "TaintFinding",
    "LLM_SOURCE_SUFFIXES",
    "LLM_SOURCE_ROOTS",
    "SINK_CALL_SUFFIXES",
]
