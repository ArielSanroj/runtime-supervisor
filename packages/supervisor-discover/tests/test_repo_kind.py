"""Framework vs app classification.

Background: scanning langchain (a framework, not an app) produced the
correct call-sites but framed them as if the user owned a deployed
agent. The single biggest mis-orientation in the report comes from
not distinguishing "this is a library to import" from "this is an
agent to run".

Heuristic is intentionally conservative — `unknown` is a valid output
when the repo is ambiguous. The classifier requires multiple positive
signals before flipping to `framework`, so apps with a `pyproject.toml`
and no Dockerfile (a common shape for small services) don't get
mis-classified.
"""
from __future__ import annotations

from pathlib import Path

from supervisor_discover.repo_kind import detect_repo_kind


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def test_langchain_shape_classifies_as_framework(tmp_path: Path):
    """Top-level pyproject + libs/ subpackages + no Dockerfile + 12
    chokepoints under /agents/ + 0 HTTP routes — the langchain shape."""
    _write(tmp_path, "pyproject.toml", '[project]\nname = "langchain"\n')
    _write(tmp_path, "libs/langchain/pyproject.toml", '[project]\nname = "langchain-core"\n')
    _write(tmp_path, "libs/langchain_v1/pyproject.toml", '[project]\nname = "langchain-v1"\n')
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=12
    )
    assert kind == "framework"


def test_pyproject_only_app_classifies_as_unknown_or_app(tmp_path: Path):
    """A small Python service that just happens to declare a package name
    in pyproject — but has 5 HTTP routes and a Dockerfile. Score lands
    in the middle (`unknown`) at worst; the banner won't fire."""
    _write(tmp_path, "pyproject.toml", '[project]\nname = "tinyservice"\n')
    _write(tmp_path, "Dockerfile", 'FROM python:3.12\nCMD ["uvicorn", "main:app"]\n')
    kind = detect_repo_kind(
        tmp_path, http_routes=5, chokepoints_in_agent_path=0
    )
    assert kind in ("app", "unknown")
    assert kind != "framework"


def test_dockerized_service_classifies_as_app(tmp_path: Path):
    """Dockerfile with `CMD ["uvicorn", ...]` — a long-lived process. App."""
    _write(tmp_path, "Dockerfile", 'FROM python:3.12\nCMD ["gunicorn", "main:app"]\n')
    _write(tmp_path, "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    kind = detect_repo_kind(
        tmp_path, http_routes=8, chokepoints_in_agent_path=0
    )
    assert kind == "app"


def test_empty_repo_classifies_as_unknown(tmp_path: Path):
    """No pyproject, no Dockerfile, no findings — heuristic stays out of
    the way. Result is `app` (default) because all conditions for
    framework fail."""
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=0
    )
    # No pyproject (-0.4) + no monorepo (-0.3) + no Dockerfile (+0.2) +
    # http_routes=0 (+0.2) = 0.4 → unknown
    assert kind == "unknown"


def test_monorepo_of_packages_recognised(tmp_path: Path):
    """`packages/` with two sub-packages, each carrying a manifest. Frame
    as monorepo even when the root pyproject is absent."""
    _write(tmp_path, "packages/foo/pyproject.toml", '[project]\nname = "foo"\n')
    _write(tmp_path, "packages/bar/package.json", '{"name": "bar"}\n')
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=15
    )
    # Monorepo (+0.3) + no Dockerfile (+0.2) + http_routes=0 (+0.2) +
    # 15 chokepoints (+0.1) = 0.8 → framework
    assert kind == "framework"
