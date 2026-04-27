"""Detect whether the scanned repo is a *framework / SDK* (no deployed
agent here — consumers wrap when they import this) vs an *app* (a
deployed runtime where the supervisor actually gates calls).

Background: the langchain repo scan recommended wrapping `XMLAgent`,
`AgentExecutor.plan`, etc. — but langchain is the framework itself. The
chokepoints in its source aren't on a deployed agent's runtime path; they
are *consumer integration surfaces* that downstream apps wrap. Keeping
the scanner's voice unchanged ("wrap this here") in that context is
misleading. The signal we need to surface is "this repo is a library —
wrap in your app, not here."

Heuristic (sums to a score; ≥ 0.6 = framework):
- Distributable package: `pyproject.toml` declares `[project] name=…` or
  the JS equivalent in `package.json` (root + monorepo subdirs).
- Mono-repo of packages: `libs/` or `packages/` or `partners/` each
  carrying their own `pyproject.toml` / `package.json`.
- No deployed runtime: absence of any `Dockerfile` whose `CMD` runs a
  long-lived process (`uvicorn`, `gunicorn`, `node`, etc.).
- No HTTP entrypoint detected by the scanner (`http_routes == 0`).

`unknown` is a valid answer — the heuristic is intentionally
conservative so generic repos stay in the default "app" presentation.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

RepoKind = Literal["framework", "app", "cli_tool", "example_template", "unknown"]

_PYPROJECT_NAME_RE = re.compile(
    r'^\s*name\s*=\s*["\']([^"\']+)["\']', re.MULTILINE
)
# Long-lived process markers — match anywhere inside a CMD/ENTRYPOINT body.
# Wrapped invocations (`CMD poetry run uvicorn …`, `CMD npm start`,
# `CMD pipenv run gunicorn …`) used to slip through because the previous
# regex anchored the process name immediately after `CMD`. fastapi-realworld
# was the canonical miss: `CMD poetry run alembic upgrade head && poetry run
# uvicorn …` reads `poetry` first and never matched.
_LONG_LIVED_PROCESS_RE = re.compile(
    r"\b(uvicorn|gunicorn|hypercorn|granian|fastapi|flask|django|"
    r"streamlit|celery|"
    r"node|deno|bun|next|nest|nuxt|astro|remix|sveltekit|"
    r"npm\s+(?:run\s+)?(?:start|dev|serve)|"
    r"yarn\s+(?:run\s+)?(?:start|dev|serve)|"
    r"pnpm\s+(?:run\s+)?(?:start|dev|serve)|"
    r"python\d?\s+-m|"
    r"rq\s+worker)\b",
    re.IGNORECASE,
)
_DOCKER_DIRECTIVE_RE = re.compile(
    r"^\s*(CMD|ENTRYPOINT)\b(.*)", re.IGNORECASE
)

# pyproject [project.scripts] / poetry [tool.poetry.scripts] declaration
# detected by section header. CLI tools (medusa CLI, agentic-controls,
# supervisor-discover itself) declare these. Distinct from a deployed
# service: nobody wraps a CLI's main() with @supervised.
_PYPROJECT_SCRIPTS_RE = re.compile(
    r"^\s*\[(?:project\.scripts|tool\.poetry\.scripts)\]", re.MULTILINE
)
# package.json `"bin"` field — same idea for Node CLIs.
_PACKAGE_BIN_RE = re.compile(r'"bin"\s*:\s*[\{"]')

# Repo names that signal "this is a starter / template / example, not a
# deployed app". Vercel / Next.js / Solid / Svelte / Astro all ship
# repos with these suffixes and the scan should reframe accordingly.
_TEMPLATE_NAME_SUFFIXES = (
    "-template", "-templates",
    "-starter", "-starters",
    "-example", "-examples",
    "-boilerplate",
    "-skeleton",
)


def _has_distributable_pyproject(root: Path) -> bool:
    """True when a top-level `pyproject.toml` declares a package name."""
    pp = root / "pyproject.toml"
    if not pp.is_file():
        return False
    try:
        text = pp.read_text(errors="ignore")
    except OSError:
        return False
    return bool(_PYPROJECT_NAME_RE.search(text))


def _is_monorepo_of_packages(root: Path) -> bool:
    """True when `libs/`, `packages/`, or `partners/` contain ≥2
    sub-directories that each ship their own `pyproject.toml` or
    `package.json`. Single-package mono-repos don't count — those are
    just slightly fancier app repos."""
    candidate_roots = ["libs", "packages", "partners"]
    for sub in candidate_roots:
        d = root / sub
        if not d.is_dir():
            continue
        package_subs = 0
        for child in d.iterdir():
            if not child.is_dir():
                continue
            if (child / "pyproject.toml").is_file() or (child / "package.json").is_file():
                package_subs += 1
        if package_subs >= 2:
            return True
    return False


def _has_long_lived_dockerfile(root: Path) -> bool:
    """True when a Dockerfile in the tree runs a long-lived process via
    CMD or ENTRYPOINT. Walks up to one level deep so a
    `services/api/Dockerfile` counts.

    Recognises shapes:
      - direct array: `CMD ["uvicorn", "main:app"]`
      - direct shell: `CMD uvicorn main:app`
      - wrapped:      `CMD poetry run uvicorn …` / `CMD npm start`
      - line-continuations: `CMD foo \\\n    && uvicorn …`
    """
    candidates = [root / "Dockerfile"]
    for sub in ("services", "apps", "deploy", "infra"):
        d = root / sub
        if d.is_dir():
            for child in d.iterdir():
                if not child.is_dir():
                    continue
                cd = child / "Dockerfile"
                if cd.is_file():
                    candidates.append(cd)
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if _dockerfile_has_long_lived_directive(text):
            return True
    return False


def _declares_cli_scripts(root: Path) -> bool:
    """True when the repo's manifest declares CLI entry points.

    Checks `pyproject.toml` for `[project.scripts]` or `[tool.poetry.scripts]`,
    and `package.json` for a top-level `"bin"` field. One match is enough:
    repos that ship a binary almost never need agent-loop wrap recommendations.
    """
    pp = root / "pyproject.toml"
    if pp.is_file():
        try:
            text = pp.read_text(errors="ignore")
        except OSError:
            text = ""
        if _PYPROJECT_SCRIPTS_RE.search(text):
            return True
    pj = root / "package.json"
    if pj.is_file():
        try:
            text = pj.read_text(errors="ignore")
        except OSError:
            text = ""
        if _PACKAGE_BIN_RE.search(text):
            return True
    return False


def _looks_like_template_repo(root: Path) -> bool:
    """True when the repo signals "this is a starter / template / example".

    Path-based: repo basename ends with one of `_TEMPLATE_NAME_SUFFIXES`,
    or the root contains a `template.json` / `registry.json` (Vercel
    / shadcn / Next.js convention)."""
    if any(root.name.lower().endswith(s) for s in _TEMPLATE_NAME_SUFFIXES):
        return True
    for marker in ("template.json", "registry.json"):
        if (root / marker).is_file():
            return True
    return False


def _dockerfile_has_long_lived_directive(text: str) -> bool:
    """Coalesce backslash-continuations, find each CMD/ENTRYPOINT directive
    body, and return True when any of them contains a long-lived process
    name. Run as a separate function so it's testable in isolation."""
    # Join `\` line continuations into a single logical line.
    logical_lines: list[str] = []
    buf = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        logical_lines.append(buf)
        buf = ""
    if buf:
        logical_lines.append(buf)
    for line in logical_lines:
        m = _DOCKER_DIRECTIVE_RE.match(line)
        if not m:
            continue
        body = m.group(2)
        if _LONG_LIVED_PROCESS_RE.search(body):
            return True
    return False


def detect_repo_kind(
    root: Path,
    *,
    http_routes: int = 0,
    chokepoints_in_agent_path: int = 0,
) -> RepoKind:
    """Classify a scanned repo as a framework, an app, a CLI tool, an
    example/template, or unknown.

    Inputs come from already-computed scanner state (passed by `build_summary`)
    so this module stays free of `Finding` imports — keeps the dependency
    direction one-way: summary → repo_kind.

    `http_routes` is the count from the http-routes scanner; non-zero is
    strong evidence of an app. `chokepoints_in_agent_path` is the count of
    agent-class findings inside a real `/agents/` directory; large numbers
    on a repo with no Dockerfile and a top-level pyproject is the langchain
    shape — many class definitions, none deployed here.

    Order: the more specific buckets (template, CLI) win before the
    framework/app score-based decision, because a CLI repo with a
    `pyproject.toml` would otherwise score as `framework` (medusa CLI
    was the canonical miss in the 10-repo benchmark).
    """
    # Most specific first — these buckets short-circuit the score logic
    # because `cli_tool` and `example_template` change the report's
    # whole framing, not just one banner.
    if _looks_like_template_repo(root):
        return "example_template"
    # CLI: declared scripts/bin AND no long-lived Dockerfile AND no real
    # HTTP surface. Tighter than "any pyproject with scripts" so a hybrid
    # repo (ships a CLI *and* runs a server) lands as `app`.
    if (
        _declares_cli_scripts(root)
        and not _has_long_lived_dockerfile(root)
        and http_routes <= 2
    ):
        return "cli_tool"

    score = 0.0

    if _has_distributable_pyproject(root):
        score += 0.4
    if _is_monorepo_of_packages(root):
        score += 0.3
    if not _has_long_lived_dockerfile(root):
        score += 0.2
    if http_routes == 0:
        score += 0.2
    # A scan that found 10+ chokepoints but zero HTTP entrypoints and zero
    # Dockerfiles is almost certainly a library exposing those classes for
    # someone else to wire up. Don't fire on small chokepoint counts — a
    # tiny app might define one Agent class and skip HTTP.
    if chokepoints_in_agent_path >= 10 and http_routes == 0:
        score += 0.1

    if score >= 0.6:
        return "framework"
    if score <= 0.2:
        return "app"
    return "unknown"
