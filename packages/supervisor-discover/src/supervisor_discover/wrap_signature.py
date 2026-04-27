"""Shared AST helpers for "wrap this method" code generation.

The "Do this now" snippet (in `start_here.py`) and the per-call-site
stubs (written by `generator.py`) both need the same thing: open a
Python file, find a specific class, pick the actual dispatcher method,
and extract its signature. Without this module the logic was duplicated
in `start_here._python_wrap_snippet`; the stub generator was using a
generic `*args, **kwargs` placeholder instead, so stubs for agent-class
findings landed with `raw_args` / `raw_kwargs` that no policy `when:`
clause could ever match.

Now stubs for agent-class findings get the same AST-derived
`payload=lambda self, year, month=None, ...: {...}` shape that the
snippet shows the dev — what they copy from the snippet matches what
they copy from the stub.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .scanners._utils import parse_python, safe_read


# Method names to prefer as the dispatcher when no method actually
# branches on a decision key. Same list that `start_here` keeps locally.
_PRIMARY_METHOD_PREFERENCE = (
    "handle", "execute", "dispatch", "run",
    "process", "route", "invoke", "call", "step",
)

# Decision-key names. Methods whose body branches on one of these
# (`if action == X` / `match action: case ...`) win against name-only
# preference — they're the actual dispatchers.
_DISPATCH_DECISION_KEYS = frozenset({
    "action", "intent", "tool", "kind", "type", "command",
    "operation", "step", "task_type", "verb",
})


@dataclass(frozen=True)
class DispatcherSignature:
    """Resolved info about the method we'd put `@supervised` on."""
    class_name: str
    method_name: str
    is_async: bool
    line: int
    arg_signature: str          # rendered `(self, year=None, month=None)`
    param_names: tuple[str, ...]  # ('self', 'year', 'month')
    parallel_methods: tuple[str, ...]   # echoed back for renderer convenience


def _decision_case_count(method: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """How many times the body branches on a decision key. Mirrored from
    `start_here._decision_case_count` so both modules stay in sync."""
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


def _pick_method(
    cls: ast.ClassDef,
    parallel_methods: tuple[str, ...],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Choose the best method on `cls` to put `@supervised` on. Mirrors
    `start_here._pick_method_for_wrap`'s priority order."""
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for child in cls.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods[child.name] = child

    if parallel_methods:
        for name in parallel_methods:
            node = methods.get(name)
            if node is not None:
                return node

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


def _format_args(args: ast.arguments) -> str:
    """Render `ast.arguments` back into `(self, year=None, month=None)`.

    Falls back to `(...)` on the (very old) interpreter that lacks
    `ast.unparse`. We don't ship for those any more but kept defensive."""
    return ast.unparse(args) if hasattr(ast, "unparse") else "..."


def _param_names(args: ast.arguments) -> tuple[str, ...]:
    """Extract the bare param names from an `ast.arguments` node — no
    annotations, no defaults, just the identifiers. Used to seed the
    stub's payload extractor with the right kwargs."""
    names: list[str] = []
    for grp in (args.posonlyargs, args.args, args.kwonlyargs):
        for a in grp:
            names.append(a.arg)
    if args.vararg is not None:
        names.append("*" + args.vararg.arg)
    if args.kwarg is not None:
        names.append("**" + args.kwarg.arg)
    return tuple(names)


def extract_dispatcher_signature(
    file: str,
    class_label: str,
    target_line: int = 0,
    parallel_methods: tuple[str, ...] = (),
) -> DispatcherSignature | None:
    """Open `file`, find the class named `class_label`, pick the dispatcher
    method, and return a structured `DispatcherSignature`.

    `class_label` may carry a `"tool: foo"` prefix from the wrap-target
    label format — it's stripped before matching.

    Returns None when:
      - the file isn't readable / parseable
      - no class matches the label
      - the matched class has no method we can recommend wrapping

    Callers handle None by falling back to the generic stub template.
    """
    suffix = Path(file).suffix.lower()
    if suffix not in (".py", ".ipynb"):
        return None
    text = safe_read(Path(file))
    if text is None:
        return None
    tree = parse_python(text)
    if tree is None:
        return None

    label = class_label.split(":", 1)[-1].strip()

    target_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == label:
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            if target_line and node.lineno <= target_line <= end:
                target_class = node
                break
            if target_class is None:
                target_class = node
    if target_class is None:
        return None

    method = _pick_method(target_class, parallel_methods)
    if method is None:
        return None

    return DispatcherSignature(
        class_name=label,
        method_name=method.name,
        is_async=isinstance(method, ast.AsyncFunctionDef),
        line=method.lineno,
        arg_signature=_format_args(method.args),
        param_names=_param_names(method.args),
        parallel_methods=parallel_methods,
    )


def render_payload_body_from_signature(sig: DispatcherSignature) -> str:
    """Render the indented Python lines that go inside `payload=lambda …: {...}`.

    Filters out `self`, *args, **kwargs from the visible mapping (they
    aren't useful as policy fields) but keeps them in the lambda's param
    list so the lambda is valid for the actual signature. Returns an
    empty string when there are no useful params, so callers can fall
    back to the generic template.
    """
    visible = [
        n for n in sig.param_names
        if n != "self" and not n.startswith("*")
    ]
    if not visible:
        return ""
    lines = [
        "        # Built from the actual dispatcher signature — edit keys/values",
        "        # to match what your policy `when:` clauses expect.",
    ]
    for name in visible:
        lines.append(f'        "{name}": {name},')
    return "\n".join(lines)


def render_lambda_args(sig: DispatcherSignature) -> str:
    """Build the lambda's parameter list from the bare param names.

    We can't reuse the unparsed `arg_signature` because type annotations
    are only legal in function defs, not lambdas (`lambda x: int = 1: x`
    is a SyntaxError). Drop annotations + defaults: the lambda accepts
    every name as a kwarg with no default, and `**kw` swallows extras
    so callers can pass the bound `self` instance without TypeError.
    """
    visible: list[str] = []
    has_vararg = False
    has_kwarg = False
    for name in sig.param_names:
        if name.startswith("**"):
            visible.append(name)
            has_kwarg = True
        elif name.startswith("*"):
            visible.append(name)
            has_vararg = True
        else:
            # Plain param — give it a default of None so the lambda is
            # invocable from any call shape, not just one matching the
            # method's declared default-list. Keeps the stub permissive
            # while the dev wires up the real call-site.
            visible.append(f"{name}=None")
    if not has_kwarg:
        visible.append("**kw")
    return ", ".join(visible)
