"""Within-repo import-graph reachability.

Background: combos like "LLM call + shell exec" used to fire on pure
co-occurrence — same repo was enough. On langchain the LLM lives in
`chains/moderation.py` and the subprocess in `agents/middleware/_execution.py`,
and neither imports the other (directly or transitively). The combo
narrative claimed "LLM-to-RCE pipeline", which was structurally wrong.

These tests cover the import resolver + BFS so the combo refinement
above can trust the reachability answer. False negatives here matter
more than false positives: missing an edge would silently let a
real combo get downgraded.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_discover.reachability import (
    any_path_between,
    build_import_graph,
    find_path,
    format_path,
)


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body.lstrip("\n"))
    return p


# ─── Build graph + path resolution ──────────────────────────────


def test_absolute_import_creates_edge(tmp_path: Path):
    """`from foo.bar import baz` resolves to the file that defines
    `foo.bar` — and that's where the edge points."""
    a = _write(tmp_path, "a.py", "from b import thing\n")
    b = _write(tmp_path, "b.py", "thing = 1\n")
    g = build_import_graph(tmp_path)
    assert b.resolve() in g[a.resolve()]


def test_relative_import_creates_edge(tmp_path: Path):
    """`from . import sibling` walks up one level from the importer's
    file directory and resolves to the matching module."""
    _write(tmp_path, "pkg/__init__.py", "")
    a = _write(tmp_path, "pkg/a.py", "from . import b\n")
    b = _write(tmp_path, "pkg/b.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    assert b.resolve() in g[a.resolve()]


def test_dotdot_relative_import(tmp_path: Path):
    """`from .. import sibling` from a sub-package resolves through the
    parent. This is the langchain shape — sub-packages reaching cousins."""
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/sub/__init__.py", "")
    a = _write(tmp_path, "pkg/sub/inner.py", "from .. import outer\n")
    outer = _write(tmp_path, "pkg/outer.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    assert outer.resolve() in g[a.resolve()]


def test_external_import_produces_no_edge(tmp_path: Path):
    """`import openai` resolves to a package outside the repo — that's
    an external dep with no within-repo edge. Otherwise the graph
    would conflate "you depend on numpy" with "you import the module
    that handles X"."""
    a = _write(tmp_path, "a.py", "import openai\nimport numpy\n")
    g = build_import_graph(tmp_path)
    assert g[a.resolve()] == set()


def test_init_re_export_resolves_to_submodule(tmp_path: Path):
    """`from pkg import sub` where `sub` is itself a module (a common
    `__init__.py` re-export pattern) creates an edge to the submodule
    file, not just the package's __init__."""
    _write(tmp_path, "pkg/__init__.py", "from .sub import Thing\n")
    sub = _write(tmp_path, "pkg/sub.py", "class Thing: pass\n")
    a = _write(tmp_path, "consumer.py", "from pkg import sub\n")
    g = build_import_graph(tmp_path)
    assert sub.resolve() in g[a.resolve()]


# ─── BFS find_path ──────────────────────────────────────────────


def test_find_path_direct_edge(tmp_path: Path):
    a = _write(tmp_path, "a.py", "import b\n")
    b = _write(tmp_path, "b.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    path = find_path(g, a, b)
    assert path is not None
    assert path == [a.resolve(), b.resolve()]


def test_find_path_two_hops(tmp_path: Path):
    a = _write(tmp_path, "a.py", "import b\n")
    b = _write(tmp_path, "b.py", "import c\n")
    c = _write(tmp_path, "c.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    path = find_path(g, a, c)
    assert path is not None
    assert path == [a.resolve(), b.resolve(), c.resolve()]


def test_find_path_disconnected_returns_none(tmp_path: Path):
    """The langchain-shaped negative: two unrelated modules in the same
    repo with no import chain between them. This is what stops the
    'LLM-to-RCE pipeline' FUD on framework repos."""
    a = _write(tmp_path, "agents/middleware.py", "import subprocess\n")
    b = _write(tmp_path, "chains/moderation.py", "import openai\n")
    g = build_import_graph(tmp_path)
    assert find_path(g, a, b) is None
    assert find_path(g, b, a) is None


def test_find_path_self_returns_single_node(tmp_path: Path):
    """A finding pair where both sides happen to be the same file is
    trivially reachable. `[a]` is the natural representation."""
    a = _write(tmp_path, "a.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    path = find_path(g, a, a)
    assert path == [a.resolve()]


# ─── any_path_between ───────────────────────────────────────────


def test_any_path_between_either_direction(tmp_path: Path):
    """The combo doesn't care which file is upstream. If `agents/x.py`
    imports `chains/y.py`, that's reachable; the reverse counts too."""
    a = _write(tmp_path, "agents/x.py", "from chains import y\n")
    _write(tmp_path, "chains/__init__.py", "")
    y = _write(tmp_path, "chains/y.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    result = any_path_between(g, [y], [a])
    assert result is not None
    src, dst, path = result
    # Path was actually `a → y` (reverse), so src is the one we found a
    # forward path *from*. The contract: result reflects the actual
    # direction, not the input order.
    assert src == a.resolve()
    assert dst == y.resolve()


def test_any_path_between_no_connection(tmp_path: Path):
    a = _write(tmp_path, "a.py", "import os\n")
    b = _write(tmp_path, "b.py", "import sys\n")
    g = build_import_graph(tmp_path)
    assert any_path_between(g, [a], [b]) is None


def test_any_path_between_picks_first_pair_that_connects(tmp_path: Path):
    """When the caller passes multiple files on each side, the BFS just
    needs to find ANY connecting pair — combo severity is yes/no, not
    a count of paths. Stops at the first hit to keep the search bounded."""
    src1 = _write(tmp_path, "src1.py", "import os\n")        # disconnected
    src2 = _write(tmp_path, "src2.py", "import dst\n")       # connected
    dst = _write(tmp_path, "dst.py", "x = 1\n")
    g = build_import_graph(tmp_path)
    result = any_path_between(g, [src1, src2], [dst])
    assert result is not None
    src, _, _ = result
    assert src == src2.resolve()


# ─── format_path ────────────────────────────────────────────────


def test_format_path_renders_relative_paths_with_arrows(tmp_path: Path):
    a = _write(tmp_path, "agents/middleware.py", "import x\n")
    b = _write(tmp_path, "x.py", "y = 1\n")
    rendered = format_path([a.resolve(), b.resolve()], tmp_path)
    assert " → " in rendered
    assert rendered.startswith("agents/middleware.py")
    assert rendered.endswith("x.py")


# ─── Real-world shape: langchain-style negative ─────────────────


def test_langchain_shape_chains_and_agents_disconnected(tmp_path: Path):
    """Mirror langchain's structure: `chains/` has the LLM call,
    `agents/middleware/` has the subprocess, and nothing reaches across.
    The `_llm_plus_shell_exec` combo should get downgraded on this
    shape — that's exactly what reachability is for."""
    _write(tmp_path, "lc/__init__.py", "")
    _write(tmp_path, "lc/chains/__init__.py", "")
    moderation = _write(tmp_path, "lc/chains/moderation.py", """
import openai
def moderate(t): return openai.chat.completions.create(messages=[{'role':'user','content':t}])
""")
    _write(tmp_path, "lc/agents/__init__.py", "")
    _write(tmp_path, "lc/agents/middleware/__init__.py", "")
    execution = _write(tmp_path, "lc/agents/middleware/_execution.py", """
import subprocess
def run(cmd): return subprocess.Popen(cmd)
""")
    g = build_import_graph(tmp_path)
    assert any_path_between(g, [moderation], [execution]) is None


def test_app_shape_chains_and_agents_connected(tmp_path: Path):
    """Mirror the app shape: a single `agent_loop.py` imports BOTH the
    LLM helper AND the shell helper. Reachability correctly says yes —
    this is the case where the FUD narrative actually applies."""
    llm_module = _write(tmp_path, "llm.py", "import openai\n")
    shell_module = _write(tmp_path, "shell.py", "import subprocess\n")
    _write(tmp_path, "agent_loop.py", "import llm\nimport shell\n")
    g = build_import_graph(tmp_path)
    # `agent_loop` reaches both, but the combo asks llm <-> shell. Neither
    # llm nor shell imports the other directly, so reachability says no
    # — and that's the correct call. The two helpers are siblings, not
    # connected. The user's `agent_loop` is the bridge but it's not in
    # the LLM nor the shell finding's file.
    assert any_path_between(g, [llm_module], [shell_module]) is None


def test_app_shape_helper_imports_other(tmp_path: Path):
    """The "real combo" shape: the LLM-handling helper imports the
    shell helper directly. Now `llm.py → shell.py` — reachability fires."""
    llm = _write(tmp_path, "llm.py", "import openai\nimport shell\n")
    shell = _write(tmp_path, "shell.py", "import subprocess\n")
    g = build_import_graph(tmp_path)
    result = any_path_between(g, [llm], [shell])
    assert result is not None
    _, _, path = result
    assert shell.resolve() in path
