"""Detect filesystem + shell execution — the agent reaches into the host OS.

Attack shapes covered:
- Agent deletes files / directories on the host (logs, user data, source code).
- Agent writes arbitrary files (overwrite configs, plant malware, exfil data).
- Agent executes shell commands (RCE-equivalent if the agent's context is attacker-controlled).

Python patterns (AST — immune to matches in comments/strings/docstrings):
  os.remove, os.unlink, shutil.rmtree, subprocess.run/Popen/call/check_call/check_output,
  os.system, os.popen, pathlib.Path(...).unlink(), open(path, 'w').

TS/JS patterns (regex): fs.unlinkSync, fs.rmSync, fs.writeFileSync,
  child_process.exec/spawn, execa.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, safe_read, ts_js_files


# Python call targets: dotted-name → (family, confidence).
# Resolved via AST so references inside comments / strings / f-strings
# can't trigger a finding.
_PY_CALL_TARGETS: dict[str, tuple[str, str]] = {
    "os.remove":               ("fs-delete", "high"),
    "os.unlink":               ("fs-delete", "high"),
    "shutil.rmtree":           ("fs-delete", "high"),
    "os.system":               ("shell-exec", "high"),
    "os.popen":                ("shell-exec", "high"),
    "subprocess.run":          ("shell-exec", "high"),
    "subprocess.Popen":        ("shell-exec", "high"),
    "subprocess.call":         ("shell-exec", "high"),
    "subprocess.check_call":   ("shell-exec", "high"),
    "subprocess.check_output": ("shell-exec", "high"),
}

# JS/TS patterns — no cheap AST, stick with regex. The patterns are anchored
# to module-level identifiers (`fs.`, `child_process.`, `execa`) so false
# positives in prose are unusual but possible. When ported to a real JS AST
# (babel-parser, tree-sitter-typescript), upgrade these to node-based checks.
_JS_DESTRUCTIVE_FS = [
    re.compile(r"\bfs\.(?:unlinkSync|rmSync|rmdirSync)\s*\("),
    re.compile(r"\bfs\.promises\.(?:unlink|rm|rmdir)\s*\("),
]
_JS_FS_WRITES = [
    re.compile(r"\bfs\.writeFileSync\s*\("),
    re.compile(r"\bfs\.promises\.writeFile\s*\("),
    re.compile(r"\bfsync?\.writeFile\s*\("),
]
_JS_SHELL_EXEC = [
    re.compile(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("),
    re.compile(r"\bexeca\s*\(|\bexeca\.command\s*\("),
]


_RATIONALES = {
    "fs-delete": (
        "Destructive filesystem op — agent can delete files / directories on the host. "
        "A prompt-injected agent could run `rm -rf` equivalent on logs, user data, or the "
        "source tree itself. Gate with @supervised('tool_use')."
    ),
    "fs-write": (
        "Filesystem write — agent can create or overwrite files. Risk: config overwrite, "
        "credential plant, payload staging. Medium confidence because most writes are "
        "legit; review per call-site."
    ),
    "shell-exec": (
        "Shell / subprocess execution — agent can run arbitrary host commands. If the "
        "command or its args flow from an LLM or from user input, this is RCE-equivalent. "
        "Gate with @supervised('tool_use') at minimum; prefer explicit tool allowlist."
    ),
}


# ─── Python AST path ───────────────────────────────────────────────────

def _dotted_name(node: ast.AST) -> str | None:
    """Resolve `a.b.c.d` attribute chain to a dotted string. Returns None
    for expressions we can't statically name (subscripts, calls, etc.)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return None
        return f"{base}.{node.attr}"
    return None


def _is_path_unlink(node: ast.Call) -> bool:
    """Match `Path(x).unlink()` — method invocation on a Path constructor."""
    if not (isinstance(node.func, ast.Attribute) and node.func.attr == "unlink"):
        return False
    receiver = node.func.value
    return (
        isinstance(receiver, ast.Call)
        and _dotted_name(receiver.func) == "Path"
    )


def _is_write_open(node: ast.Call) -> bool:
    """Match `open(path, 'w')` / `open(path, mode='w')` with any w-family mode."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "open"):
        return False
    # positional mode arg
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        v = node.args[1].value
        if isinstance(v, str) and v.startswith("w"):
            return True
    # keyword mode arg
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            v = kw.value.value
            if isinstance(v, str) and v.startswith("w"):
                return True
    return False


def _refine_python_severity(node: ast.Call, family: str, default: str) -> tuple[str, bool]:
    """Inspect the AST node args to refine severity by call-site context.

    Returns (new_severity, refined_flag). The refined_flag goes into extra so
    the UI can hint "downgraded because args are hardcoded" when relevant.

    Rules:
    - subprocess.* with `shell=True` keyword          → high (always RCE-shaped)
    - subprocess.* with first arg = list of constants → low  (`["git", "log"]`)
    - subprocess.* with first arg = constant string   → low  (`"git log"` is
                                                              uncommon but still hardcoded)
    - open(...) with first arg = constant string      → low  (hardcoded path)
    - everything else: keep default
    """
    if family == "shell-exec":
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                return ("high", default != "high")
        first_arg = node.args[0] if node.args else None
        if isinstance(first_arg, ast.List) and all(
            isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            for elt in first_arg.elts
        ):
            return ("low", True)
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            return ("low", True)
        return (default, False)

    if family == "fs-write":
        first_arg = node.args[0] if node.args else None
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            return ("low", True)
        return (default, False)

    # fs-delete: even a hardcoded path is risky if it's your source tree.
    return (default, False)


def _scan_python(path: Path, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    source_lines = text.splitlines()
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        label: str | None = None
        family: str | None = None
        severity: str | None = None

        name = _dotted_name(node.func)
        if name in _PY_CALL_TARGETS:
            family, severity = _PY_CALL_TARGETS[name]
            label = name
        elif _is_path_unlink(node):
            family, severity, label = "fs-delete", "high", "Path.unlink"
        elif _is_write_open(node):
            family, severity, label = "fs-write", "medium", "open-w"

        if label is None:
            continue

        # Refine severity by inspecting args — hardcoded list/string args
        # for subprocess.run / open are much lower risk than variable args.
        severity, refined = _refine_python_severity(node, family, severity)

        line = node.lineno
        # Use the real source line as the snippet — gives the UI a useful
        # slice of the call site (`subprocess.run(["echo", event])` vs the
        # generic `subprocess.run(`).
        snippet = source_lines[line - 1].strip()[:80] if 0 <= line - 1 < len(source_lines) else f"{label}("
        out.append(Finding(
            scanner="fs-shell",
            file=str(path),
            line=line,
            snippet=snippet,
            suggested_action_type="tool_use",
            confidence=severity,  # type: ignore[arg-type]
            rationale=_RATIONALES[family],
            extra={"family": family, "label": label, "severity_refined": refined},
        ))
    return out


# ─── JS/TS regex path ──────────────────────────────────────────────────

def _scan_js(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for family, patterns in (
        ("fs-delete", _JS_DESTRUCTIVE_FS),
        ("fs-write", _JS_FS_WRITES),
        ("shell-exec", _JS_SHELL_EXEC),
    ):
        severity = "medium" if family == "fs-write" else "high"
        for pattern in patterns:
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                out.append(Finding(
                    scanner="fs-shell",
                    file=str(path),
                    line=line,
                    snippet=m.group(0)[:80],
                    suggested_action_type="tool_use",
                    confidence=severity,
                    rationale=_RATIONALES[family],
                    extra={"family": family, "label": m.group(0).rstrip("(")},
                ))
    return out


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_python(path, text))
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        findings.extend(_scan_js(path, text))
    return findings
