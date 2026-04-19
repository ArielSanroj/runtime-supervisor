"""Shared scanner helpers."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

_PY_GLOB = "**/*.py"
_TS_GLOBS = ("**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.mjs")

_SKIP_DIRS = {
    # build + package dirs (safe: never project source)
    "node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build",
    ".next", "target", ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "coverage", "htmlcov", ".nox", ".turbo", ".parcel-cache",
    "site-packages", "node_modules.bak",
    # language-specific caches
    ".npm", ".gem", ".cargo", ".rustup", ".pnpm-store", ".yarn",
    ".pyenv", ".nvm", ".rbenv",
    # macOS system dirs — only matter if someone scans $HOME, which the
    # CLI already refuses separately. NOT including Downloads / Music /
    # Pictures / etc because those are places where devs commonly clone
    # repos and we'd over-exclude real project files.
    "Library", "Applications", ".Trash", ".cache",
    ".docker", ".android", ".gradle", ".m2",
}


def _walk(root: Path, globs: tuple[str, ...]) -> Iterator[Path]:
    for pattern in globs:
        for path in root.glob(pattern):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def python_files(root: Path) -> Iterator[Path]:
    yield from _walk(root, (_PY_GLOB,))


def ts_js_files(root: Path) -> Iterator[Path]:
    yield from _walk(root, _TS_GLOBS)


def config_files(root: Path) -> Iterator[Path]:
    for candidate in [
        "crontab", ".crontab", "crontab.txt",
        ".github/workflows",
        "docker-compose.yml", "docker-compose.yaml",
    ]:
        p = root / candidate
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from p.glob("*.yml")
            yield from p.glob("*.yaml")
