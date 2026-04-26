"""Detect the repo's dep manager + app entry point so START_HERE.md can ship
a "Step 0 — install the SDK" block that actually runs.

Without this, every START_HERE.md silently assumes the dev already has
`supervisor-guards` installed and `configure_supervisor()` called at startup.
The first copy-paste of the wrap snippet then fails with `ModuleNotFoundError`,
and the dev has to dig through docs to figure out the install + wiring step.
We saw this on the first three real-repo deployments.

The module is conservative on purpose:
  - Detection misses → return None → the renderer falls back to a generic
    block instead of crashing. False negatives produce more guidance, never
    less guidance.
  - Detection hits → return a small, frozen dataclass the renderer reads to
    pick the install command, the entry-point file:line, and whether to
    skip the `configure_supervisor()` paste because the dev already wired it.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .scanners._utils import parse_python, safe_read


# ─── Data shapes ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class DepManager:
    """How to install an extra dependency in this repo."""
    kind: str               # "pip", "poetry", "uv", "pipenv", "npm", "pnpm", "yarn"
    language: str           # "python" | "ts"
    manifest_path: str      # absolute, e.g. "/repo/backend/requirements.txt"
    install_cmd: str        # ready-to-paste single-line shell command


@dataclass(frozen=True)
class EntryPoint:
    """Where to drop `configure_supervisor()` so it runs once at startup."""
    file: str               # absolute path
    line: int               # line of the framework instantiation
    framework: str          # "fastapi" | "flask" | "django" | "hono" | "express" | "deno-serve" | "generic"
    language: str           # "python" | "ts"


@dataclass(frozen=True)
class BootstrapInfo:
    """Everything the START_HERE renderer needs for its Step 0 block.

    `manager == None` means we couldn't classify the repo's dep manager —
    the renderer emits a generic block. `entrypoint == None` means we
    couldn't find a framework instantiation — the renderer says "drop the
    call where you bootstrap your app". `configure_already_called == True`
    means the renderer should omit the configure-call paste (the dev did
    it on a previous PR).
    """
    manager: DepManager | None
    entrypoint: EntryPoint | None
    configure_already_called: bool


# ─── Dep manager detection ──────────────────────────────────────────


# Filenames that pin which dep manager the repo uses. Order matters when
# multiple are present: lock files dominate the manifest because they tell
# us which CLI was actually used.
_LOCK_TO_MANAGER = (
    ("uv.lock", "uv"),
    ("poetry.lock", "poetry"),
    ("Pipfile.lock", "pipenv"),
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
)

_PY_PACKAGE_NAME = "supervisor-guards"
_TS_PACKAGE_NAME = "@runtime-supervisor/guards"
_PY_VERSION_PIN = ">=0.3"


def _shallow_files(root: Path, names: Iterable[str], max_depth: int = 3) -> list[Path]:
    """Return matching files up to `max_depth` levels deep, skipping common
    cache / build dirs. Walks breadth-first and stops at depth.
    """
    skip_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        "dist", "build", ".next", "target", ".tox", ".turbo",
        "coverage", "htmlcov", "runtime-supervisor",
    }
    out: list[Path] = []
    target_names = set(names)
    queue: list[tuple[Path, int]] = [(root, 0)]
    while queue:
        directory, depth = queue.pop(0)
        if depth > max_depth:
            continue
        try:
            entries = list(directory.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in skip_dirs or entry.name.startswith("."):
                    continue
                queue.append((entry, depth + 1))
            elif entry.is_file() and entry.name in target_names:
                out.append(entry)
    return out


def _pyproject_kind(path: Path) -> str | None:
    """Read a `pyproject.toml` and decide whether it's poetry/uv/pip-compatible.

    - `[tool.poetry]` → "poetry"
    - `[project]` (PEP 621) AND a `uv.lock` next to it → "uv"
    - `[project]` only → "pip"
    """
    text = safe_read(path)
    if text is None:
        return None
    has_poetry = "[tool.poetry]" in text
    has_pep621 = re.search(r"^\[project\]", text, re.MULTILINE) is not None
    if has_poetry:
        return "poetry"
    if has_pep621:
        if (path.parent / "uv.lock").exists():
            return "uv"
        return "pip"
    return None


def _build_install_cmd(kind: str, manifest_path: Path) -> str:
    """One-line install command for `kind`. Quoted version specifier for shell
    safety (`>=` is harmless but consistency helps if pin grows).

    For `pip`, the command differs by manifest:
      - `requirements.txt`  → append + `pip install -r`. Reproducible in CI.
      - `pyproject.toml`    → plain `pip install` (the user adds the dep to
        `[project.dependencies]` themselves; we don't sed pyproject.toml
        because the file format is fragile and varies by build backend).
    """
    if kind == "pip":
        if manifest_path.name == "pyproject.toml":
            return f"pip install '{_PY_PACKAGE_NAME}{_PY_VERSION_PIN}'  # then add to [project.dependencies] in pyproject.toml"
        rel = manifest_path.name
        return f'echo "{_PY_PACKAGE_NAME}{_PY_VERSION_PIN}" >> {rel} && pip install -r {rel}'
    if kind == "poetry":
        return f"poetry add '{_PY_PACKAGE_NAME}{_PY_VERSION_PIN}'"
    if kind == "uv":
        return f"uv add '{_PY_PACKAGE_NAME}{_PY_VERSION_PIN}'"
    if kind == "pipenv":
        return f"pipenv install '{_PY_PACKAGE_NAME}{_PY_VERSION_PIN}'"
    if kind == "pnpm":
        return f"pnpm add {_TS_PACKAGE_NAME}"
    if kind == "yarn":
        return f"yarn add {_TS_PACKAGE_NAME}"
    if kind == "npm":
        return f"npm install {_TS_PACKAGE_NAME}"
    return f"# unknown manager — install '{_PY_PACKAGE_NAME}' or '{_TS_PACKAGE_NAME}' manually"


def detect_dep_manager(
    root: Path,
    *,
    prefer_language: str | None = None,
) -> DepManager | None:
    """Classify the repo's dep manager. Returns None when no manifest is found.

    `prefer_language` ("python" or "ts") tilts the choice in monorepos where
    both Python and JS manifests exist — e.g. a repo whose top wrap target is
    a `.ts` file should get the JS manager block, not the Python one.
    """
    py_locks = _shallow_files(root, [name for name, _ in _LOCK_TO_MANAGER if name.endswith(".lock") or name == "Pipfile.lock"])
    ts_locks = _shallow_files(root, ("pnpm-lock.yaml", "yarn.lock", "package-lock.json"))
    py_manifests = _shallow_files(root, ("pyproject.toml", "requirements.txt"))
    js_manifests = _shallow_files(root, ("package.json",))

    # Pick a Python candidate.
    py_candidate: tuple[str, Path] | None = None
    # Lock files win — they tell us the actual CLI used.
    for lock in py_locks:
        for name, kind in _LOCK_TO_MANAGER:
            if lock.name == name and kind in ("uv", "poetry", "pipenv"):
                # Prefer the manifest in the same directory.
                manifest = lock.parent / "pyproject.toml"
                if manifest.exists():
                    py_candidate = (kind, manifest)
                else:
                    py_candidate = (kind, lock)
                break
        if py_candidate:
            break
    if py_candidate is None:
        for manifest in py_manifests:
            if manifest.name == "pyproject.toml":
                kind = _pyproject_kind(manifest)
                if kind:
                    py_candidate = (kind, manifest)
                    break
        if py_candidate is None:
            for manifest in py_manifests:
                if manifest.name.startswith("requirements") and manifest.name.endswith(".txt"):
                    py_candidate = ("pip", manifest)
                    break

    # Pick a JS candidate.
    js_candidate: tuple[str, Path] | None = None
    for lock in ts_locks:
        for name, kind in _LOCK_TO_MANAGER:
            if lock.name == name and kind in ("pnpm", "yarn", "npm"):
                manifest = lock.parent / "package.json"
                if manifest.exists():
                    js_candidate = (kind, manifest)
                else:
                    js_candidate = (kind, lock)
                break
        if js_candidate:
            break
    if js_candidate is None and js_manifests:
        # `package.json` with no lock → assume npm (standard default).
        js_candidate = ("npm", js_manifests[0])

    # Resolve language preference for monorepos.
    if py_candidate and js_candidate:
        if prefer_language == "ts":
            chosen = js_candidate
        elif prefer_language == "python":
            chosen = py_candidate
        else:
            # No hint — bias towards Python because Python wraps are typically
            # higher leverage in agent codebases.
            chosen = py_candidate
    elif py_candidate:
        chosen = py_candidate
    elif js_candidate:
        chosen = js_candidate
    else:
        return None

    kind, manifest = chosen
    language = "ts" if kind in ("npm", "pnpm", "yarn") else "python"
    return DepManager(
        kind=kind,
        language=language,
        manifest_path=str(manifest),
        install_cmd=_build_install_cmd(kind, manifest),
    )


# ─── App entry point detection ──────────────────────────────────────


_PY_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("fastapi", re.compile(r"\bFastAPI\s*\(")),
    ("flask", re.compile(r"\bFlask\s*\(")),
    ("django", re.compile(r"\bget_wsgi_application\s*\(|\bget_asgi_application\s*\(")),
    ("starlette", re.compile(r"\bStarlette\s*\(")),
    # Generic fallback — `app = FOO()` with FOO unknown but `.run(`/`.start(` near.
    ("generic", re.compile(r"^\s*app\s*=\s*\w+\s*\(", re.MULTILINE)),
]

_TS_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hono", re.compile(r"\bnew\s+Hono\s*\(|\bHono\s*\(\s*\)")),
    ("express", re.compile(r"\bexpress\s*\(\s*\)")),
    ("deno-serve", re.compile(r"\bDeno\.serve\s*\(")),
    ("nestjs", re.compile(r"\bNestFactory\.create\s*\(")),
    ("nextjs-handler", re.compile(r"export\s+default\s+function\s+handler\s*\(")),
]

# Filenames worth checking first (cheap path-based prior). Order matters.
_PY_ENTRYPOINT_NAMES = ("app.py", "main.py", "server.py", "wsgi.py", "asgi.py", "__main__.py")
_TS_ENTRYPOINT_NAMES = ("index.ts", "main.ts", "server.ts", "app.ts", "index.tsx")


def _scan_for_framework(path: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> tuple[str, int] | None:
    """Return (framework, line) of the first pattern hit, or None."""
    text = safe_read(path)
    if text is None:
        return None
    for framework, pattern in patterns:
        m = pattern.search(text)
        if m is not None:
            line = text[: m.start()].count("\n") + 1
            return framework, line
    return None


def detect_app_entrypoint(
    root: Path,
    *,
    language: str = "python",
    near_files: list[str] | None = None,
) -> EntryPoint | None:
    """Find the file that instantiates the web framework.

    `language` selects which patterns to try. `near_files` is an optional list
    of file paths (e.g. the dirs of the top wrap targets) to bias the search —
    we walk those dirs first before falling back to the repo root, which helps
    in monorepos where the actual app lives in `apps/api/` rather than the
    top-level dir.
    """
    if language not in ("python", "ts"):
        return None

    candidate_names = _PY_ENTRYPOINT_NAMES if language == "python" else _TS_ENTRYPOINT_NAMES
    patterns = _PY_FRAMEWORK_PATTERNS if language == "python" else _TS_FRAMEWORK_PATTERNS

    # Step 1: search the dirs containing the wrap targets first (most likely
    # the actual app dir in a monorepo).
    seen: set[Path] = set()
    search_dirs: list[Path] = []
    for nf in near_files or []:
        try:
            parent = Path(nf).resolve().parent
            while parent != parent.parent:
                if parent in seen:
                    break
                if root.resolve() in parent.parents or parent == root.resolve():
                    search_dirs.append(parent)
                    seen.add(parent)
                else:
                    break
                parent = parent.parent
        except OSError:
            continue

    # Step 2: append common dirs from root.
    for sub in ("", "src", "app", "backend", "api", "server"):
        directory = root / sub if sub else root
        if directory.is_dir() and directory not in seen:
            search_dirs.append(directory)
            seen.add(directory)

    for directory in search_dirs:
        for name in candidate_names:
            candidate = directory / name
            if candidate.is_file():
                hit = _scan_for_framework(candidate, patterns)
                if hit:
                    framework, line = hit
                    return EntryPoint(
                        file=str(candidate),
                        line=line,
                        framework=framework,
                        language=language,
                    )

    # Step 3: shallow walk for any candidate-named file we missed.
    for path in _shallow_files(root, candidate_names):
        hit = _scan_for_framework(path, patterns)
        if hit:
            framework, line = hit
            return EntryPoint(
                file=str(path), line=line, framework=framework, language=language,
            )

    return None


# ─── configure_supervisor() detection ───────────────────────────────


_CONFIGURE_NAMES = frozenset({"configure_supervisor", "configure", "configureSupervisor"})


def is_configure_already_called(entry_point: EntryPoint) -> bool:
    """True when the entry point already invokes `configure_supervisor()` or
    similar SDK init. Conservative — false positives just mean the renderer
    omits the wiring block when the dev still needs it (recoverable).
    """
    text = safe_read(Path(entry_point.file))
    if text is None:
        return False

    if entry_point.language == "python":
        tree = parse_python(text)
        if tree is None:
            # Fall back to regex.
            return bool(re.search(r"\bconfigure_supervisor\s*\(", text))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in _CONFIGURE_NAMES:
                return True
        return False

    # TS/JS: regex is enough; we don't ship a TS AST.
    return bool(
        re.search(r"\bconfigureSupervisor\s*\(", text)
        or re.search(r"\bconfigure_supervisor\s*\(", text)
    )


# ─── Public assembly ────────────────────────────────────────────────


def build_bootstrap_info(
    root: Path,
    *,
    prefer_language: str | None = None,
    near_files: list[str] | None = None,
) -> BootstrapInfo:
    """Top-level entry: detect manager, entry point, configure-call status.

    Always returns a `BootstrapInfo`; the renderer is responsible for
    emitting nothing when both `manager` and `entrypoint` are None
    (full miss → keep START_HERE quiet rather than ship a useless block).
    """
    manager = detect_dep_manager(root, prefer_language=prefer_language)
    language = prefer_language
    if language is None and manager is not None:
        language = manager.language
    if language is None:
        language = "python"
    entrypoint = detect_app_entrypoint(root, language=language, near_files=near_files)
    configure_called = bool(entrypoint and is_configure_already_called(entrypoint))
    return BootstrapInfo(
        manager=manager,
        entrypoint=entrypoint,
        configure_already_called=configure_called,
    )
