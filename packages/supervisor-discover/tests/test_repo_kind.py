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


def test_wrapped_cmd_classifies_as_app(tmp_path: Path):
    """`CMD poetry run uvicorn …` (the fastapi-realworld shape) is a
    long-lived deployable process even though the literal first token
    after CMD is `poetry`. The classifier must recognise the wrapper —
    score must NOT add the +0.2 "no long-lived dockerfile" bonus, so
    the result lands in app/unknown territory, never framework."""
    _write(tmp_path, "pyproject.toml", '[project]\nname = "fastapi-realworld"\n')
    _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.9\n"
        "CMD poetry run alembic upgrade head && \\\n"
        "    poetry run uvicorn --host=0.0.0.0 app.main:app\n",
    )
    kind = detect_repo_kind(
        tmp_path, http_routes=19, chokepoints_in_agent_path=0
    )
    assert kind in ("app", "unknown")
    assert kind != "framework"


def test_npm_start_cmd_classifies_as_app(tmp_path: Path):
    """`CMD npm start` is the canonical Node deployment shape — wrapper
    invocation that the old regex missed entirely."""
    _write(tmp_path, "package.json", '{"name": "node-app"}\n')
    _write(tmp_path, "Dockerfile", 'FROM node:20\nCMD npm start\n')
    kind = detect_repo_kind(
        tmp_path, http_routes=4, chokepoints_in_agent_path=0
    )
    # No pyproject (-0.4) + no monorepo (-0.3) + long-lived Dockerfile
    # detected (-0.2) + http_routes>0 (-0.2) = 0 → app.
    assert kind == "app"


def test_entrypoint_directive_recognised(tmp_path: Path):
    """ENTRYPOINT-only Dockerfiles (gunicorn entrypoints) are also
    long-lived. Previously the regex only checked CMD."""
    _write(tmp_path, "pyproject.toml", '[project]\nname = "service"\n')
    _write(
        tmp_path,
        "Dockerfile",
        'FROM python:3.12\nENTRYPOINT ["gunicorn", "main:app"]\n',
    )
    kind = detect_repo_kind(
        tmp_path, http_routes=3, chokepoints_in_agent_path=0
    )
    assert kind in ("app", "unknown")
    assert kind != "framework"


def test_pyproject_with_scripts_classifies_as_cli_tool(tmp_path: Path):
    """A repo whose pyproject.toml declares `[project.scripts]` and ships
    no Dockerfile / minimal HTTP surface is a CLI tool, not an app or
    framework. medusa CLI was the canonical miss in the 10-repo
    benchmark — got tagged framework when it's a developer tool."""
    _write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "supervisor-discover"\n'
        '[project.scripts]\nsupervisor-discover = "supervisor_discover.cli:main"\n',
    )
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=0,
    )
    assert kind == "cli_tool"


def test_node_package_with_bin_classifies_as_cli_tool(tmp_path: Path):
    """package.json with a `bin` field on the root → Node CLI tool."""
    _write(
        tmp_path,
        "package.json",
        '{"name": "vercel", "bin": {"vercel": "./bin/vercel"}}\n',
    )
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=0,
    )
    assert kind == "cli_tool"


def test_template_repo_basename_classifies_as_example_template(tmp_path: Path):
    """Repos named `*-template` / `*-starter` / `*-example` are scaffold
    repos. The benchmark's `nextjs-subscription-payments` (a starter)
    used to land as `app` — wrong category for the playbook."""
    template = tmp_path / "nextjs-subscription-starter"
    template.mkdir()
    _write(template, "package.json", '{"name": "starter"}\n')
    kind = detect_repo_kind(
        template, http_routes=4, chokepoints_in_agent_path=0,
    )
    assert kind == "example_template"


def test_registry_json_marks_example_template(tmp_path: Path):
    """shadcn / Vercel marketplace conventions ship a `registry.json`
    or `template.json` at root. Treat as example/template regardless
    of basename."""
    _write(tmp_path, "registry.json", '{"name": "ui-blocks"}\n')
    kind = detect_repo_kind(
        tmp_path, http_routes=0, chokepoints_in_agent_path=0,
    )
    assert kind == "example_template"


def test_cli_with_dockerfile_falls_through_to_app(tmp_path: Path):
    """Hybrid repos that ship a CLI *and* run a server (Dockerfile with
    long-lived process) get classified as `app` — the deployable surface
    wins because that's what actually needs guardrails."""
    _write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "hybrid"\n'
        '[project.scripts]\nhybrid = "hybrid.cli:main"\n',
    )
    _write(
        tmp_path,
        "Dockerfile",
        'FROM python:3.12\nCMD ["uvicorn", "main:app"]\n',
    )
    kind = detect_repo_kind(
        tmp_path, http_routes=8, chokepoints_in_agent_path=0,
    )
    # Long-lived Dockerfile present + http_routes>0 → app/unknown, NOT cli_tool.
    assert kind in ("app", "unknown")
    assert kind != "cli_tool"


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
