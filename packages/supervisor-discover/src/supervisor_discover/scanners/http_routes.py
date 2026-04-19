"""Find HTTP route handlers.

Python: ast walker looking for Flask (`@app.route`), FastAPI (`@router.post/get/put/delete`),
Django (`urls.py` patterns with path() calls).

TS/JS: regex for Next.js API routes (files under `app/**/route.ts` or `pages/api/**`), Express
app.get/post handlers.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, ts_js_files

_PY_HTTP_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
_TS_EXPRESS_PATTERN = re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(", re.IGNORECASE)
_TS_NEXT_API_PATH = re.compile(r"(?:app/.*?/route\.(?:ts|js)|pages/api/.+\.(?:ts|js))$")


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                name = _decorator_name(deco)
                if not name:
                    continue
                last = name.rsplit(".", 1)[-1]
                if last in _PY_HTTP_DECORATORS and ("route" in name or "." in name):
                    findings.append(Finding(
                        scanner="http-routes",
                        file=str(path),
                        line=node.lineno,
                        snippet=f"{name}  # {node.name}",
                        suggested_action_type="other",
                        confidence="medium",
                        rationale=f"Python HTTP handler `{node.name}` decorated with `@{name}`. "
                                  "The supervisor should gate this route if it performs state-changing operations.",
                        extra={"function": node.name, "framework": _guess_framework(name)},
                    ))
                    break
    return findings


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST | None = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
    if isinstance(node, ast.Name):
        return node.id
    return None


def _guess_framework(name: str) -> str:
    if "app.route" in name:
        return "flask"
    if "router." in name or "app.get" in name or "app.post" in name:
        return "fastapi"
    return "unknown"


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        rel = str(path).replace(str(root) + "/", "")
        is_next_api = bool(_TS_NEXT_API_PATH.search(rel))
        text = path.read_text(errors="ignore")

        if is_next_api:
            # Next.js app router: export async function GET/POST/... at top level
            for m in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="http-routes",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type="other",
                    confidence="high",
                    rationale=f"Next.js API route handler {m.group(1)} at `{rel}`. "
                              "If this route mutates state or calls external services, it needs supervision.",
                    extra={"method": m.group(1), "framework": "next-app-router"},
                ))

        for m in _TS_EXPRESS_PATTERN.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                scanner="http-routes",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type="other",
                confidence="medium",
                rationale="Express/Fastify-style HTTP handler — verify whether it does a mutation that needs a guard.",
                extra={"framework": "express"},
            ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
