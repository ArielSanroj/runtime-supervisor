"""Shared scanner helpers."""
from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path


def safe_read(path: Path) -> str | None:
    """Read text, returning None on any filesystem or decode error.

    macOS TCC blocks reads under ~/Downloads/Documents/Desktop unless the
    terminal has Full Disk Access, and raises PermissionError. Broken
    symlinks and unreadable special files raise OSError. The scanner must
    skip a single unreadable file, not crash the whole scan.
    """
    try:
        return path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None

_PY_GLOB = "**/*.py"
_TS_GLOBS = ("**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.mjs")

_SKIP_DIRS = {
    # build + package dirs (safe: never project source)
    "node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build",
    ".next", "target", ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "coverage", "htmlcov", ".nox", ".turbo", ".parcel-cache",
    "site-packages", "node_modules.bak",
    # worktrees from git/claude — copies of the same source, cause duplicates
    "worktrees",
    # the scanner's own output — avoid re-scanning generated stubs on reruns
    "runtime-supervisor",
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
    """Iterate matching files under `root`, skipping build/cache dirs.

    Skip check uses the path RELATIVE to `root` — not the absolute path —
    because a user's repo may legitimately live inside a host directory
    whose name is in _SKIP_DIRS. Example: repos in Dropbox on macOS live
    at `~/Library/CloudStorage/Dropbox/<repo>`; if we checked absolute
    parts, "Library" would match and we'd skip every file.
    """
    for pattern in globs:
        for path in root.glob(pattern):
            try:
                rel_parts = path.relative_to(root).parts
            except ValueError:
                # path is not a descendant of root (shouldn't happen with
                # glob, but be defensive). Treat as skip.
                continue
            if any(part in _SKIP_DIRS for part in rel_parts):
                continue
            if path.is_file():
                yield path


def python_files(root: Path) -> Iterator[Path]:
    yield from _walk(root, (_PY_GLOB,))


def ts_js_files(root: Path) -> Iterator[Path]:
    yield from _walk(root, _TS_GLOBS)


def dotted_name(node: ast.AST) -> str | None:
    """Resolve `a.b.c.d` AST attribute chain to a dotted string. Returns None
    for expressions that aren't a straight attribute/name chain (subscripts,
    nested calls, etc.).

    Used by scanners to match SDK calls like `sgMail.send(...)` or
    `subprocess.run(...)` against a known allow-list of call targets,
    replacing text-regex matching that leaks into comments and strings.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def iter_python_calls(text: str) -> Iterator[ast.Call]:
    """Yield every `ast.Call` node in `text`. Silently yields nothing for
    files with syntax errors — scanners skip those rather than crash."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def match_dotted_call(call: ast.Call, targets: dict[str, object]) -> tuple[str, object] | None:
    """If `call.func` resolves to a dotted name listed in `targets`, return
    `(name, targets[name])`. Otherwise None. Also matches a suffix of the
    dotted chain — e.g. target `messages.create` matches both
    `client.messages.create(...)` and `anthropic.messages.create(...)` —
    so scanners can use short suffixes as 'trailing path' signatures."""
    name = dotted_name(call.func)
    if name is None:
        return None
    if name in targets:
        return name, targets[name]
    # Allow suffix matches on dotted chains: target "messages.create"
    # matches `x.y.messages.create`.
    for target in targets:
        if "." in target and name.endswith("." + target):
            return target, targets[target]
    return None


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
