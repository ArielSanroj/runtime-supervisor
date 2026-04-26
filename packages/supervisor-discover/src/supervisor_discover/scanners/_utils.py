"""Shared scanner helpers."""
from __future__ import annotations

import ast
import json
import re
import warnings
from collections.abc import Iterator
from pathlib import Path


def parse_python(text: str) -> ast.Module | None:
    """Parse `text` as Python, returning None on syntax errors.

    Suppresses `SyntaxWarning` (e.g. invalid escape sequences like `'\\%'`)
    raised by the target source — those warnings come from the user's repo,
    not from our own code, so leaking them to stderr just adds noise.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def safe_read(path: Path) -> str | None:
    """Read text, returning None on any filesystem or decode error.

    For .ipynb files, returns the concatenated Python source from code cells
    so existing Python scanners (fs_shell, llm_calls, agent_orchestrators…)
    can run against notebook code without changes. Line numbers in findings
    will point into the synthetic flat source — the path identifies the
    notebook, the snippet shows the actual code, and grep reaches the cell.

    macOS TCC blocks reads under ~/Downloads/Documents/Desktop unless the
    terminal has Full Disk Access, and raises PermissionError. Broken
    symlinks and unreadable special files raise OSError. The scanner must
    skip a single unreadable file, not crash the whole scan.
    """
    try:
        if path.suffix == ".ipynb":
            return _extract_notebook_python(path)
        return path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _extract_notebook_python(path: Path) -> str:
    """Parse a Jupyter notebook and return concatenated Python from code cells.

    Magics (`%foo`, `!foo`, `?foo`) are commented out so AST parsing doesn't
    fail on them. Cells are separated by `# === notebook cell N ===` so the
    extracted source roughly maps back to cell boundaries when read alone.
    """
    raw = path.read_text(errors="ignore")
    nb = json.loads(raw)
    blocks: list[str] = []
    for i, cell in enumerate(nb.get("cells") or []):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source") or ""
        if isinstance(source, list):
            source = "".join(source)
        clean: list[str] = []
        for ln in source.splitlines():
            stripped = ln.lstrip()
            # IPython magics + shell escapes aren't valid Python — comment them
            # out so ast.parse() doesn't bail on the whole notebook.
            if stripped.startswith(("%", "!", "?")):
                clean.append("# " + ln)
            else:
                clean.append(ln)
        blocks.append(f"# === notebook cell {i} ===\n" + "\n".join(clean))
    return "\n\n".join(blocks) + "\n"


_PY_GLOBS = ("**/*.py", "**/*.ipynb")
_TS_GLOBS = ("**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.mjs")

# Filename patterns that mean "compiled / bundled output, not source". Real
# call-sites never live in these — they're webpack chunks, minified bundles,
# or source maps. Reporting them as findings produces "wrap a hashed bundle
# file" recommendations which are nonsense.
_BUNDLE_SUFFIXES = (
    ".bundle.js", ".bundle.mjs", ".bundle.cjs",
    ".min.js", ".min.mjs", ".min.cjs",
    ".chunk.js", ".chunk.mjs",
    ".map",
)

# Webpack/Rollup hashed chunks: `5566.c76ea61eb723ee84e2cf.js`,
# `main.a1b2c3d4.js`, etc. Matched on the BASENAME — never on directories,
# because some apps ship `<hash>` directory names that aren't bundles.
_BUNDLE_HASHED_NAME = re.compile(r"^[\w.-]+\.[a-f0-9]{8,}\.(?:js|mjs|cjs|css)$", re.IGNORECASE)


def _is_bundle_artifact(path: Path) -> bool:
    """True for compiled bundles, minified output, source maps, hashed chunks."""
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in _BUNDLE_SUFFIXES):
        return True
    if _BUNDLE_HASHED_NAME.match(path.name):
        return True
    return False

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
            if not path.is_file():
                continue
            if _is_bundle_artifact(path):
                continue
            yield path


def python_files(root: Path) -> Iterator[Path]:
    """Yield Python source paths — `.py` plus `.ipynb` notebooks.

    Notebook handling is transparent to scanners: `safe_read()` extracts the
    code cells and returns a concatenated Python source, so the same AST /
    regex detectors fire on notebook code without scanner-side changes.
    """
    yield from _walk(root, _PY_GLOBS)


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
    tree = parse_python(text)
    if tree is None:
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


# ─── HTTP verb detection (URL → mutation vs read) ────────────────────
#
# URL-pattern scanners (calendar, certain payment endpoints) match the URL
# regardless of the HTTP verb. A `fetch(url)` against `…/calendar/v3/.../events`
# is a list/read; a `fetch(url, { method: "POST" })` is a mutation. Reporting
# the read as a "calendar mutation" misleads the dev — they wrap a GET endpoint
# they didn't need to.
#
# This helper looks at a small window around the URL match and decides whether
# the verb is GET (read) or a write verb. If it can't tell, returns None and
# the caller keeps the original behavior.

_HTTP_VERB_WRITE = ("POST", "PUT", "PATCH", "DELETE")
_HTTP_VERB_READ = ("GET", "HEAD")

_RE_METHOD_KEY = re.compile(
    r"""(?:method|verb)\s*[:=]\s*['"]([A-Z]+)['"]""",
    re.IGNORECASE,
)
_RE_REQUESTS_VERB = re.compile(
    r"\b(?:requests|httpx|axios|fetch)\.(get|post|put|patch|delete|head)\s*\(",
    re.IGNORECASE,
)
# Plain `fetch(` / `await fetch(` — JavaScript / Deno / Edge runtime API.
# Default verb is GET unless an options object explicitly sets `method:`.
_RE_PLAIN_FETCH = re.compile(r"\bawait\s+fetch\s*\(|\bfetch\s*\(", re.IGNORECASE)


def detect_http_verb_near(text: str, match_start: int, *, window: int = 240) -> str | None:
    """Inspect a window around `match_start` and return "READ", "WRITE", or None.

    Searches a slice of `text` from `match_start - window` to `match_start +
    window` for explicit method markers (`method: "POST"`) or HTTP-client verb
    calls (`requests.post(`, plain `fetch(...)`). The window is small on
    purpose — we want the verb that goes WITH this URL, not one elsewhere in
    the file.

    Returns None when ambiguous so callers can keep the existing finding.
    """
    lo = max(0, match_start - window)
    hi = min(len(text), match_start + window)
    snippet = text[lo:hi]

    m = _RE_METHOD_KEY.search(snippet)
    if m:
        verb = m.group(1).upper()
        if verb in _HTTP_VERB_WRITE:
            return "WRITE"
        if verb in _HTTP_VERB_READ:
            return "READ"

    m = _RE_REQUESTS_VERB.search(snippet)
    if m:
        verb = m.group(1).upper()
        if verb in _HTTP_VERB_WRITE:
            return "WRITE"
        if verb in _HTTP_VERB_READ:
            return "READ"

    # Plain `fetch(url, …)` with NO `method:` anywhere in the window → defaults
    # to GET (a calendar list query, not a mutation). The `method:` check
    # above already short-circuits the WRITE case, so reaching here means we
    # saw `fetch(` and no method key — safe to classify READ.
    if _RE_PLAIN_FETCH.search(snippet):
        return "READ"

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
