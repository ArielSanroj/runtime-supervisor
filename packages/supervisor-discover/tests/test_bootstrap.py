"""Tests for the Step 0 bootstrap detection.

The point of bootstrap.py is to look at a repo and answer three questions
that the START_HERE.md "Step 0 — install the SDK" block needs:
  1. Which dep manager? (pip / poetry / uv / pnpm / yarn / npm)
  2. Where do I add `configure_supervisor()`? (FastAPI / Flask / Hono / …)
  3. Has the dev already wired it on a previous PR?

False positives here render an unnecessary install block — annoying.
False negatives leave the dev to guess on first scan — much worse. The
classifier biases toward emitting *some* guidance whenever it can.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from supervisor_discover.bootstrap import (
    BootstrapInfo,
    DepManager,
    EntryPoint,
    build_bootstrap_info,
    detect_app_entrypoint,
    detect_dep_manager,
    is_configure_already_called,
)


def _write(tmp: Path, name: str, body: str) -> Path:
    """Write `body` to `tmp/name`, creating dirs. Returns the path."""
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ─── Dep manager detection ──────────────────────────────────────


def test_detect_pip_requirements_txt(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "fastapi>=0.110\nsqlalchemy>=2\n")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "pip"
    assert mgr.language == "python"
    assert "pip install" in mgr.install_cmd
    assert "supervisor-guards" in mgr.install_cmd


def test_detect_poetry_pyproject(tmp_path: Path):
    _write(tmp_path, "pyproject.toml", "[tool.poetry]\nname = \"x\"\n")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "poetry"
    assert mgr.install_cmd.startswith("poetry add")


def test_detect_uv_when_lockfile_present(tmp_path: Path):
    """`pyproject.toml` with PEP 621 `[project]` AND `uv.lock` in the same
    directory → kind == 'uv', not plain 'pip'."""
    _write(tmp_path, "pyproject.toml", "[project]\nname = \"x\"\nversion = \"0\"\n")
    _write(tmp_path, "uv.lock", "")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "uv"
    assert mgr.install_cmd.startswith("uv add")


def test_detect_pip_for_pep621_without_uvlock(tmp_path: Path):
    _write(tmp_path, "pyproject.toml", "[project]\nname = \"x\"\nversion = \"0\"\n")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "pip"


def test_detect_pnpm(tmp_path: Path):
    _write(tmp_path, "package.json", '{"name":"x"}')
    _write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "pnpm"
    assert mgr.language == "ts"
    assert mgr.install_cmd == "pnpm add @runtime-supervisor/guards"


def test_detect_yarn(tmp_path: Path):
    _write(tmp_path, "package.json", '{"name":"x"}')
    _write(tmp_path, "yarn.lock", "")
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None and mgr.kind == "yarn"


def test_detect_npm_default_when_no_lock(tmp_path: Path):
    _write(tmp_path, "package.json", '{"name":"x"}')
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None and mgr.kind == "npm"


def test_detect_no_manifest_returns_none(tmp_path: Path):
    mgr = detect_dep_manager(tmp_path)
    assert mgr is None


def test_monorepo_prefers_python_by_default(tmp_path: Path):
    """Both `backend/requirements.txt` and `frontend/package.json` exist.
    With no language hint, default to Python (typical agent codebase)."""
    _write(tmp_path, "backend/requirements.txt", "fastapi\n")
    _write(tmp_path, "frontend/package.json", '{"name":"web"}')
    mgr = detect_dep_manager(tmp_path)
    assert mgr is not None
    assert mgr.kind == "pip"


def test_monorepo_picks_ts_when_hint_says_ts(tmp_path: Path):
    """Wrap target lives in `.ts` → `prefer_language='ts'` → JS manager picked
    even when a Python one is also present."""
    _write(tmp_path, "backend/requirements.txt", "fastapi\n")
    _write(tmp_path, "frontend/package.json", '{"name":"web"}')
    _write(tmp_path, "frontend/pnpm-lock.yaml", "")
    mgr = detect_dep_manager(tmp_path, prefer_language="ts")
    assert mgr is not None and mgr.kind == "pnpm"


# ─── App entry point detection ──────────────────────────────────


def test_detect_fastapi_entrypoint(tmp_path: Path):
    _write(tmp_path, "src/api/app.py", """
from fastapi import FastAPI
app = FastAPI(title="x")
""")
    ep = detect_app_entrypoint(tmp_path, language="python")
    assert ep is not None
    assert ep.framework == "fastapi"
    assert "app.py" in ep.file
    assert ep.line >= 2


def test_detect_flask_entrypoint(tmp_path: Path):
    _write(tmp_path, "main.py", "from flask import Flask\napp = Flask(__name__)\n")
    ep = detect_app_entrypoint(tmp_path, language="python")
    assert ep is not None and ep.framework == "flask"


def test_detect_hono_entrypoint(tmp_path: Path):
    _write(tmp_path, "supabase/functions/orchestrator/index.ts", """
import { Hono } from "hono";
const app = new Hono();
""")
    ep = detect_app_entrypoint(tmp_path, language="ts")
    assert ep is not None
    assert ep.framework == "hono"
    assert "index.ts" in ep.file


def test_detect_express_entrypoint(tmp_path: Path):
    _write(tmp_path, "server.ts", "import express from 'express';\nconst app = express();\n")
    ep = detect_app_entrypoint(tmp_path, language="ts")
    assert ep is not None and ep.framework == "express"


def test_detect_returns_none_when_no_entrypoint(tmp_path: Path):
    _write(tmp_path, "lib.py", "def add(a, b): return a + b")
    ep = detect_app_entrypoint(tmp_path, language="python")
    assert ep is None


def test_near_files_biases_search_toward_wrap_target_dir(tmp_path: Path):
    """Two FastAPI apps in different subdirs — `near_files` pointing into one
    of them must surface that one first."""
    _write(tmp_path, "apps/legacy/app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(tmp_path, "apps/api/app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    ep = detect_app_entrypoint(
        tmp_path, language="python",
        near_files=[str(tmp_path / "apps/api/agents/orchestrator.py")],
    )
    assert ep is not None
    assert "apps/api/app.py" in ep.file


# ─── configure_supervisor() detection ───────────────────────────


def test_is_configure_already_called_python_true(tmp_path: Path):
    src = _write(tmp_path, "app.py", """
from supervisor_guards import configure_supervisor

configure_supervisor()
""")
    ep = EntryPoint(file=str(src), line=1, framework="fastapi", language="python")
    assert is_configure_already_called(ep) is True


def test_is_configure_already_called_python_false(tmp_path: Path):
    src = _write(tmp_path, "app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    ep = EntryPoint(file=str(src), line=1, framework="fastapi", language="python")
    assert is_configure_already_called(ep) is False


def test_is_configure_already_called_via_method_attr(tmp_path: Path):
    """Some repos call `sg.configure(...)` instead of `configure_supervisor()`."""
    src = _write(tmp_path, "app.py", """
import supervisor_guards as sg
sg.configure()
""")
    ep = EntryPoint(file=str(src), line=1, framework="fastapi", language="python")
    assert is_configure_already_called(ep) is True


def test_is_configure_already_called_ts_true(tmp_path: Path):
    src = _write(tmp_path, "index.ts", """
import { configureSupervisor } from "@runtime-supervisor/guards";
configureSupervisor();
""")
    ep = EntryPoint(file=str(src), line=1, framework="hono", language="ts")
    assert is_configure_already_called(ep) is True


def test_is_configure_already_called_unparseable_python_falls_back_to_regex(tmp_path: Path):
    """Even when AST parsing fails (syntax error), the regex fallback should
    still see `configure_supervisor()` and return True. This protects users
    whose entry point happens to have a transient syntax error during scan."""
    src = _write(tmp_path, "app.py", "configure_supervisor()\nbroken syntax (((")
    ep = EntryPoint(file=str(src), line=1, framework="fastapi", language="python")
    assert is_configure_already_called(ep) is True


# ─── Public assembly ────────────────────────────────────────────


def test_build_bootstrap_info_full_python_repo(tmp_path: Path):
    _write(tmp_path, "requirements.txt", "fastapi\n")
    _write(tmp_path, "src/api/app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    bs = build_bootstrap_info(tmp_path, prefer_language="python")
    assert isinstance(bs, BootstrapInfo)
    assert bs.manager is not None and bs.manager.kind == "pip"
    assert bs.entrypoint is not None and bs.entrypoint.framework == "fastapi"
    assert bs.configure_already_called is False


def test_build_bootstrap_info_skips_configure_block_when_already_called(tmp_path: Path):
    """Mirrors supervincent: app.py already imports + calls
    `configure_supervisor()`. The renderer will use this to omit the wiring
    block instead of re-recommending what's done."""
    _write(tmp_path, "requirements.txt", "fastapi\n")
    _write(tmp_path, "src/api/app.py", """
from fastapi import FastAPI
from supervisor_guards import configure_supervisor

configure_supervisor()
app = FastAPI()
""")
    bs = build_bootstrap_info(tmp_path, prefer_language="python")
    assert bs.configure_already_called is True


def test_build_bootstrap_info_empty_repo(tmp_path: Path):
    bs = build_bootstrap_info(tmp_path)
    assert bs.manager is None
    assert bs.entrypoint is None
    assert bs.configure_already_called is False
