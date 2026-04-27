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

RepoKind = Literal["framework", "app", "unknown"]

_PYPROJECT_NAME_RE = re.compile(
    r'^\s*name\s*=\s*["\']([^"\']+)["\']', re.MULTILINE
)
_DOCKER_CMD_PROCESS_RE = re.compile(
    r'CMD\s*\[?\s*["\']?'
    r"(uvicorn|gunicorn|hypercorn|granian|fastapi|flask|django|"
    r"node|deno|bun|next|nest|nuxt|astro|remix|sveltekit|"
    r"python\s+-m|python3\s+-m)",
    re.IGNORECASE,
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
    CMD. Walks up to one level deep so a `services/api/Dockerfile`
    counts."""
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
        if _DOCKER_CMD_PROCESS_RE.search(text):
            return True
    return False


def detect_repo_kind(
    root: Path,
    *,
    http_routes: int = 0,
    chokepoints_in_agent_path: int = 0,
) -> RepoKind:
    """Classify a scanned repo as a framework, an app, or unknown.

    Inputs come from already-computed scanner state (passed by `build_summary`)
    so this module stays free of `Finding` imports — keeps the dependency
    direction one-way: summary → repo_kind.

    `http_routes` is the count from the http-routes scanner; non-zero is
    strong evidence of an app. `chokepoints_in_agent_path` is the count of
    agent-class findings inside a real `/agents/` directory; large numbers
    on a repo with no Dockerfile and a top-level pyproject is the langchain
    shape — many class definitions, none deployed here.
    """
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
