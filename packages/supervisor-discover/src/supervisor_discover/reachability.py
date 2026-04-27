"""Within-repo import-graph reachability for combo refinement.

Background: combos like "LLM call + shell exec" used to fire on pure
co-occurrence — the two findings just had to live in the same repo. On
langchain (the framework) the LLM call lives in `chains/moderation.py`
and the subprocess in `agents/middleware/_execution.py`. Neither imports
the other (directly or transitively); the prompt-injection-controls-RCE
narrative is wrong by construction. We softened the copy in `combos.py`
to "co-occurrence" but the severity stayed `critical`, which kept the
panel screaming. With reachability we can demote those false positives
explicitly: when no import path connects the LLM module to the
shell-exec module, drop severity to `low` and rephrase the narrative.

Why imports, not full taint: a real taint analysis (track values from
LLM responses to subprocess args across module boundaries) is weeks of
work and breaks on any metaprogramming. Import reachability is a strict
*upper bound*: if two modules don't share any import path, there is no
data-flow between them — period. False negatives are impossible. False
positives (modules connected by imports but not actually piping data)
remain, but the combo copy already says "if any code path connects
these, that path is RCE-equivalent" — that framing matches what
import reachability detects.

Limitations the caller should know:
- Dynamic imports (`importlib.import_module`, `__import__`, plugin
  systems) are invisible. If a repo loads handlers from a config file at
  runtime, this won't see those edges. Treat the result as "best-effort".
- Star imports (`from foo import *`) count as edges to `foo`, which is
  correct for reachability but loses information about which symbols
  are actually used.
- Conditional imports (`if TYPE_CHECKING: import x`) count as edges.
  Ditto imports inside function bodies. We don't try to be precise about
  *when* the import happens — only whether one module can reach another.
"""
from __future__ import annotations

import ast
import os
from collections import deque
from pathlib import Path

from .scanners._utils import parse_python, python_files, safe_read


# ─── Module path resolution ──────────────────────────────────────────


def _module_key(path: Path, root: Path) -> str:
    """Convert an absolute file path inside `root` into a stable dotted
    module key. We strip the repo root + drop the `.py` suffix and
    replace `/` with `.`. `__init__.py` collapses to its parent package.

    Examples (root = /tmp/repo):
      /tmp/repo/foo/bar.py        → "foo.bar"
      /tmp/repo/foo/__init__.py   → "foo"
      /tmp/repo/main.py           → "main"
    """
    try:
        rel = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return ""
    parts = list(rel.parts)
    if not parts:
        return ""
    last = parts[-1]
    if last.endswith(".py"):
        last = last[:-3]
    if last == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = last
    return ".".join(parts)


def _build_module_index(root: Path) -> dict[str, Path]:
    """Map dotted module name → file path for every Python source file
    under `root`. Used to resolve absolute imports in `_resolve_import`.
    Built once per scan, queried per AST node — keeps the resolver O(1)
    instead of O(files) per import.
    """
    index: dict[str, Path] = {}
    for path in python_files(root):
        key = _module_key(path, root)
        if not key:
            continue
        # First writer wins. Two files producing the same module key would
        # be unusual (shadowing / namespace package collision); the scan
        # path order is deterministic so behaviour stays stable.
        index.setdefault(key, path)
    return index


def _relative_base_rel(
    importer: Path, level: int, root: Path,
) -> str | None:
    """Resolve a relative import's base directory (where the leading
    dots stop) and return its dotted module path, or None when the
    base lands outside `root`.

    `level=1` means `from .x import y` — base is the importer's parent.
    `level=2` means `from ..x import y` — base is the importer's
    grandparent. Empty string means the base is the repo root itself.
    """
    base = importer.resolve().parent
    for _ in range(level - 1):
        base = base.parent
    root_abs = root.resolve()
    if base != root_abs:
        try:
            return base.relative_to(root_abs).as_posix().replace("/", ".")
        except (OSError, ValueError):
            return None
    return ""


def _resolve_absolute(
    module: str, module_index: dict[str, Path],
) -> Path | None:
    """Resolve `import foo.bar` / `from foo.bar import baz` against the
    repo's module index. Walks the dotted name from longest to shortest
    so a top-level `import foo.bar` resolves to `foo/bar.py` but falls
    back to `foo/__init__.py` when only the package exists.

    Returns None when no within-repo file matches — that's an external
    dependency (numpy / langchain installed via pip) and contributes no
    edge to the within-repo graph.
    """
    parts = module.split(".")
    while parts:
        key = ".".join(parts)
        path = module_index.get(key)
        if path is not None:
            return path
        parts.pop()
    return None


def _imports_from_ast(
    file: Path, root: Path, module_index: dict[str, Path],
) -> set[Path]:
    """Return the set of files imported by `file` that resolve to within
    the repo. External deps and unresolved references are dropped — the
    graph only tracks within-repo edges.
    """
    text = safe_read(file)
    if text is None:
        return set()
    tree = parse_python(text)
    if tree is None:
        return set()
    out: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                resolved = _resolve_absolute(alias.name, module_index)
                if resolved is not None:
                    out.add(resolved)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                base_pkg = _relative_base_rel(file, node.level, root)
                if base_pkg is None:
                    continue
                # `from .pkg import x` → resolve `pkg` against base, plus
                # try each `x` as a sub-submodule of `pkg`.
                # `from . import x`    → each `x` is a submodule of base
                # directly (most common for `__init__.py` re-exports).
                module_prefix = base_pkg
                if node.module:
                    module_prefix = (
                        (base_pkg + "." + node.module).strip(".") if base_pkg
                        else node.module
                    )
                    direct = module_index.get(module_prefix)
                    if direct is not None:
                        out.add(direct)
                for alias in node.names:
                    sub_key = (
                        (module_prefix + "." + alias.name).strip(".")
                        if module_prefix
                        else alias.name
                    )
                    sub = module_index.get(sub_key)
                    if sub is not None:
                        out.add(sub)
            elif node.module is not None:
                resolved = _resolve_absolute(node.module, module_index)
                if resolved is not None:
                    out.add(resolved)
                # `from package import sub_mod` may also reach a module.
                for alias in node.names:
                    sub_key = node.module + "." + alias.name
                    sub = module_index.get(sub_key)
                    if sub is not None:
                        out.add(sub)
    return out


# ─── Public API ──────────────────────────────────────────────────────


def build_import_graph(root: Path) -> dict[Path, set[Path]]:
    """Build the within-repo import graph as `file → set(imported files)`.

    Keys are absolute paths (resolved to canonical form). Edges point
    from importer to imported. External deps (anything not under `root`)
    are dropped — they can't carry data-flow back into the repo.
    """
    root = root.resolve()
    module_index = _build_module_index(root)
    graph: dict[Path, set[Path]] = {}
    for path in module_index.values():
        graph[path.resolve()] = {p.resolve() for p in _imports_from_ast(path, root, module_index)}
    return graph


def find_path(
    graph: dict[Path, set[Path]], src: Path, dst: Path,
) -> list[Path] | None:
    """BFS from `src` to `dst`. Returns the shortest module path
    (inclusive of both endpoints), or None when no within-repo import
    chain connects them.

    `src == dst` returns `[src]` — a single-file finding pair is trivially
    reachable.
    """
    src = src.resolve()
    dst = dst.resolve()
    if src not in graph:
        return None
    if src == dst:
        return [src]
    visited: set[Path] = {src}
    queue: deque[tuple[Path, list[Path]]] = deque([(src, [src])])
    while queue:
        node, path = queue.popleft()
        for neighbor in graph.get(node, ()):
            if neighbor == dst:
                return path + [neighbor]
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, path + [neighbor]))
    return None


def any_path_between(
    graph: dict[Path, set[Path]], src_files: list[Path], dst_files: list[Path],
) -> tuple[Path, Path, list[Path]] | None:
    """Find ANY reachability between any source-finding file and any
    destination-finding file. Tries `src → dst` first, then `dst → src`
    so the caller doesn't have to worry about which family is upstream.

    Returns `(src, dst, path)` for the first pair that connects, or None
    when nothing reaches anything. Capped at the first hit because combos
    only need a yes/no — there's no value in enumerating every pair.
    """
    for src in src_files:
        for dst in dst_files:
            path = find_path(graph, src, dst)
            if path is not None:
                return (src, dst, path)
            # Try the reverse direction too — shell-exec module
            # importing the LLM module is just as much a data-flow
            # surface as the LLM module importing the shell module.
            rev = find_path(graph, dst, src)
            if rev is not None:
                return (dst, src, rev)
    return None


def _format_path(path: list[Path], root: Path) -> str:
    """Human-readable render of a resolved import chain — relative to
    `root`, joined with → arrows. Used in combo narratives so the dev
    sees `agents/middleware.py → chains/moderation.py` instead of
    absolute /tmp paths."""
    root_abs = root.resolve()
    parts: list[str] = []
    for p in path:
        try:
            rel = p.resolve().relative_to(root_abs).as_posix()
        except (OSError, ValueError):
            rel = p.name
        parts.append(rel)
    return " → ".join(parts)


def format_path(path: list[Path], root: Path) -> str:
    """Public alias of `_format_path`. Combos and tests use it to render
    a reachability chain in user-facing copy."""
    return _format_path(path, root)


__all__ = [
    "build_import_graph",
    "find_path",
    "any_path_between",
    "format_path",
]
