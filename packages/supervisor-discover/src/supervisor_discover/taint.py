"""Light taint analysis — demote findings whose sensitive arg is provably
system-derived.

Today the scanner classifies findings by call shape alone. That marks
`os.unlink(path)` as high regardless of where `path` came from. The
reviewer flagged real cases on supervincent and castor-1 where `path`
was a `tempfile.NamedTemporaryFile()` result — system-controlled, not
LLM-reachable, but still rendering as "agent can delete files".

This module runs ONCE after every scanner finishes. For each finding
that's currently medium/high and whose sensitive arg is a variable, we:

  1. Find the Call node at the reported line.
  2. Extract the "interesting arg" (the path / command / target).
  3. If it's a Name or `<Name>.attr`, walk back through `Assign` nodes in
     the enclosing function to find where the Name was last set.
  4. Classify the RHS:
       - `tempfile.*` / `os.environ.*` / `os.getenv` / `settings.X`
         / `config.X`  → SYSTEM-derived
       - String / bytes literal                                 → CONSTANT
       - Anything else                                          → UNKNOWN

Demotion fires when the source is SYSTEM or CONSTANT — those are the
two cases the reviewer asked us to suppress. UNKNOWN keeps the original
severity (be conservative — don't downgrade real risks just because we
can't trace the data flow).

This is intra-procedural and shallow on purpose. Cross-function flow,
dataclass attributes, framework-magic params (FastAPI dependencies,
Pydantic models) need a real taint engine — out of scope here. The
narrow approach captures ~30-50% of medium FPs the reviewer pointed at,
and stays simple enough to validate by inspection.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .findings import Finding
from .scanners._utils import dotted_name, parse_python, safe_read


# Calls whose RESULT is system-controlled. Matched by exact dotted name on
# `_dotted_name(call.func)`. Add aliases as we encounter them.
_SYSTEM_DERIVED_CALLS = frozenset({
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryFile",
    "tempfile.SpooledTemporaryFile",
    "tempfile.mkstemp",
    "tempfile.mkdtemp",
    "tempfile.gettempdir",
    "tempfile.gettempprefix",
    "os.environ.get",
    "os.getenv",
    "Path.cwd",
    "Path.home",
    "os.getcwd",
    "os.path.expanduser",
    "os.path.expandvars",
    "platform.python_version",
    "sys.executable",   # not a call but used like one in subprocess args
})

# Attribute chains (root.attr1.attr2) that indicate "config from
# the host", not user input. We match by prefix so settings.tenant.url
# counts under "settings.*".
_SYSTEM_ATTRIBUTE_PREFIXES = (
    "settings.", "config.", "Config.", "SETTINGS.", "ENV.",
    "os.environ", "os.path",  # `os.path.tempdir` / `os.environ['X']`
)


# Public ENUM-like return values. Strings are nicer than ints for the
# `extra` payload and for tests reading findings.json.
TAINT_SYSTEM = "system"
TAINT_CONSTANT = "constant"
TAINT_UNKNOWN = "unknown"


def _arg_for_taint(call: ast.Call) -> ast.expr | None:
    """Return the AST node that represents the sensitive input for `call`.

    Different fs-shell-style call shapes carry the path / command in
    different positions. We handle the common shapes; anything else
    returns None and the caller leaves the finding alone.
    """
    func = call.func

    # Bare names: eval(x), exec(x), open(x, "w") → first positional arg
    if isinstance(func, ast.Name):
        return call.args[0] if call.args else None

    # Attribute access: receiver.method(args) — the path can live in args
    # OR in the receiver chain depending on the API.
    if isinstance(func, ast.Attribute):
        attr = func.attr
        # Path(p).unlink() / Path(p).rmtree() — no args, the path is the arg
        # to the constructor in the receiver chain.
        if attr in ("unlink", "rmtree", "remove", "rename", "replace"):
            if call.args:
                return call.args[0]
            receiver = func.value
            if isinstance(receiver, ast.Call) and receiver.args:
                return receiver.args[0]
            return receiver
        # subprocess.run(cmd) / subprocess.Popen(cmd_list) → first arg
        if attr in ("run", "Popen", "call", "check_call", "check_output", "system", "popen"):
            return call.args[0] if call.args else None
        # Generic: assume first arg is the sensitive one (open(p, "w"),
        # os.unlink(p), shutil.rmtree(p), …).
        return call.args[0] if call.args else None

    return call.args[0] if call.args else None


def _enclosing_function(tree: ast.Module, target_line: int) -> ast.AST | None:
    """Return the smallest function / async-function whose body covers
    `target_line`. When no enclosing function is found (module-level call),
    return the module itself — variables can still be defined there."""
    best: ast.AST | None = None
    best_span = float("inf")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        if node.lineno <= target_line <= end:
            span = end - node.lineno
            if span < best_span:
                best = node
                best_span = span
    return best or tree


def _find_assignment(name: str, scope: ast.AST, before_line: int) -> ast.expr | None:
    """Most recent `name = <expr>` whose line is strictly before `before_line`.

    Searches the scope's body (and nested blocks). Augmented assigns
    (`name += x`) are ignored — we want the value, and an augmented
    assign requires the prior value, so the earlier plain assign is what
    matters. Returns the RHS expression or None.
    """
    most_recent: ast.Assign | None = None
    for node in ast.walk(scope):
        if not isinstance(node, ast.Assign):
            continue
        if node.lineno >= before_line:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                if most_recent is None or node.lineno > most_recent.lineno:
                    most_recent = node
                break
    return most_recent.value if most_recent else None


def _dotted_attribute_chain(node: ast.expr) -> str | None:
    """Resolve `a.b.c` to the dotted string. None for non-chains.

    Used to match `settings.MY_PATH` against `_SYSTEM_ATTRIBUTE_PREFIXES`.
    """
    parts: list[str] = []
    current = node
    while True:
        if isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        elif isinstance(current, ast.Name):
            parts.insert(0, current.id)
            return ".".join(parts)
        else:
            return None


def _classify_rhs(rhs: ast.expr) -> str:
    """Return one of TAINT_SYSTEM / TAINT_CONSTANT / TAINT_UNKNOWN.

    Conservative: only return SYSTEM/CONSTANT when we're sure. Anything
    else (function results from unknown sources, attribute chains we
    don't recognize, comprehensions) returns UNKNOWN.
    """
    if isinstance(rhs, ast.Constant):
        return TAINT_CONSTANT
    if isinstance(rhs, ast.Call):
        callee = dotted_name(rhs.func)
        if callee and callee in _SYSTEM_DERIVED_CALLS:
            return TAINT_SYSTEM
        # `os.environ.get(...)` parses as Call(func=Attribute(Attribute(...)))
        # which dotted_name handles, but be defensive.
        if callee and callee.startswith("os.environ"):
            return TAINT_SYSTEM
        return TAINT_UNKNOWN
    if isinstance(rhs, ast.Subscript):
        # `os.environ["KEY"]` — the value here is the Subscript.
        chain = _dotted_attribute_chain(rhs.value)
        if chain and chain.startswith("os.environ"):
            return TAINT_SYSTEM
        return TAINT_UNKNOWN
    if isinstance(rhs, ast.Attribute):
        chain = _dotted_attribute_chain(rhs)
        if chain is None:
            return TAINT_UNKNOWN
        if any(chain.startswith(p) for p in _SYSTEM_ATTRIBUTE_PREFIXES):
            return TAINT_SYSTEM
        return TAINT_UNKNOWN
    if isinstance(rhs, ast.JoinedStr):
        # f-string: classify based on the parts. A joined string composed
        # entirely of constants and system-classified vars is system; if
        # any part is unknown, return unknown.
        all_safe = True
        for part in rhs.values:
            if isinstance(part, ast.Constant):
                continue
            if isinstance(part, ast.FormattedValue):
                inner = _classify_rhs(part.value)
                if inner not in (TAINT_SYSTEM, TAINT_CONSTANT):
                    all_safe = False
                    break
            else:
                all_safe = False
                break
        return TAINT_SYSTEM if all_safe else TAINT_UNKNOWN
    return TAINT_UNKNOWN


def _classify_arg(arg: ast.expr, scope: ast.AST, before_line: int) -> str:
    """Classify a single arg as SYSTEM / CONSTANT / UNKNOWN.

    For Names and Attribute-chains we walk back to the most recent assign
    in the same scope and classify the RHS. Constants / system attribute
    chains are classified directly. Anything else returns UNKNOWN.
    """
    # Direct constant.
    if isinstance(arg, ast.Constant):
        return TAINT_CONSTANT

    # System-attribute chains: settings.X, config.Y, os.environ['Z'].
    if isinstance(arg, (ast.Attribute, ast.Subscript)):
        direct = _classify_rhs(arg)
        if direct in (TAINT_SYSTEM, TAINT_CONSTANT):
            return direct

    # Names: walk back to the assign.
    if isinstance(arg, ast.Name):
        rhs = _find_assignment(arg.id, scope, before_line)
        if rhs is None:
            return TAINT_UNKNOWN
        return _classify_rhs(rhs)

    # Attribute on a Name: e.g. `tmp.name` — walk back to the Name's assign,
    # accept its classification. We don't track field-level taint.
    if isinstance(arg, ast.Attribute):
        base = arg.value
        if isinstance(base, ast.Name):
            rhs = _find_assignment(base.id, scope, before_line)
            if rhs is None:
                return TAINT_UNKNOWN
            return _classify_rhs(rhs)

    # f-strings, lists, tuples, calls — too complex for this pass.
    if isinstance(arg, ast.JoinedStr):
        return _classify_rhs(arg)

    return TAINT_UNKNOWN


def _is_demotable_finding(f: Finding) -> bool:
    """Only fs-shell findings (delete / write / shell-exec / code-eval) on
    Python files at medium/high confidence are eligible. Other scanners
    use different arg shapes and are out of scope for this pass."""
    if f.scanner != "fs-shell":
        return False
    if f.confidence == "low":
        return False
    if not f.file.endswith((".py", ".ipynb")):
        return False
    family = (f.extra or {}).get("family")
    return family in {"fs-delete", "fs-write", "shell-exec", "code-eval"}


def _find_call_at_line(tree: ast.Module, line: int) -> ast.Call | None:
    """Return the first Call node whose lineno equals `line`. There can
    be multiple calls on one line (`f(g(x))`); we pick the outermost,
    which is the one the scanner reported."""
    candidates: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno == line:
            candidates.append(node)
    if not candidates:
        return None
    # Outermost = the one whose end_lineno extends the most. Calls on the
    # same line tie-break by start col; smaller col offset = outer.
    candidates.sort(key=lambda c: (c.col_offset, -getattr(c, "end_col_offset", 0)))
    return candidates[0]


def annotate_findings(findings: list[Finding]) -> list[Finding]:
    """Mutate `findings` to demote system/constant-derived ones to low.

    Each demoted finding gets:
      - `confidence = "low"`
      - `extra["taint_source"]` = "system" or "constant"
      - `extra["taint_demoted"] = True`

    Findings with UNKNOWN classification are left alone — better to keep
    a real risk visible than to silently demote it. Non-Python files and
    non-fs-shell scanners are skipped entirely.

    Idempotent — re-runs leave already-demoted findings as-is.
    """
    file_cache: dict[str, ast.Module | None] = {}
    for f in findings:
        if not _is_demotable_finding(f):
            continue
        if (f.extra or {}).get("taint_demoted"):
            continue

        if f.file not in file_cache:
            text = safe_read(Path(f.file))
            file_cache[f.file] = parse_python(text) if text is not None else None
        tree = file_cache[f.file]
        if tree is None:
            continue

        call = _find_call_at_line(tree, f.line)
        if call is None:
            continue
        arg = _arg_for_taint(call)
        if arg is None:
            continue

        scope = _enclosing_function(tree, f.line)
        if scope is None:
            continue
        classification = _classify_arg(arg, scope, f.line)

        if classification in (TAINT_SYSTEM, TAINT_CONSTANT):
            f.confidence = "low"  # type: ignore[assignment]
            f.extra = {
                **(f.extra or {}),
                "taint_source": classification,
                "taint_demoted": True,
            }
    return findings
