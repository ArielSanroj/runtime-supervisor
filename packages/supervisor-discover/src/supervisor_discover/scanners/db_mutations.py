"""Find DB mutations that need supervision.

Heuristic-driven; tuned for recall (easy to silence false positives later).

Flags:
- SQLAlchemy: session.commit() in files that also call .delete() / .update() / .add()
- Raw SQL: UPDATE / DELETE / INSERT statements in source files (case-insensitive)
- Prisma (TS): `prisma.<model>.{update,delete,upsert}(`
- TypeORM (TS): `.remove(`, `.save(` on repositories

Elevates suggestion to `account_change` when the file/table name hints at
users/accounts/customers; `data_access` when tables look like pii_*/logs.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterator

from ..findings import Finding
from ._utils import parse_python, python_files, safe_read, ts_js_files

_ACCOUNT_HINTS = re.compile(r"\b(users?|accounts?|customers?|profiles?|identities)\b", re.IGNORECASE)
_PII_HINTS = re.compile(r"\b(emails?|phones?|ssn|addresses?|payments?|cards?)\b", re.IGNORECASE)

# Strict SQL matchers — each verb requires its canonical partner token to
# reduce false positives on prose like "Update your config" / "update ad
# campaign" (common in README, docstrings, error messages, HTML). The old
# loose regex was flagging 11 noise-matches in one marketingagent scan.
_PY_SQL_UPDATE = re.compile(r"\bUPDATE\s+(\w+)\s+SET\b", re.IGNORECASE)
_PY_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\s+(\w+)", re.IGNORECASE)
_PY_SQL_INSERT = re.compile(r"\bINSERT\s+INTO\s+(\w+)", re.IGNORECASE)

_PY_COMMIT = re.compile(r"\bsession\.commit\(\)")
_PY_SESSION_MUTATE = re.compile(r"\bsession\.(add|delete|merge)\b")

_TS_PRISMA = re.compile(r"\bprisma\.(\w+)\.(update|delete|upsert|create|createMany|deleteMany|updateMany)\s*\(")
_TS_TYPEORM = re.compile(r"\.(remove|save|delete|update)\s*\(", re.IGNORECASE)
_TS_SQL_UPDATE = re.compile(r"\bUPDATE\s+(\w+)\s+SET\b", re.IGNORECASE)
_TS_SQL_DELETE = re.compile(r"\bDELETE\s+FROM\s+(\w+)", re.IGNORECASE)
_TS_SQL_INSERT = re.compile(r"\bINSERT\s+INTO\s+(\w+)", re.IGNORECASE)


def _suggest(table_or_path: str) -> str:
    if _ACCOUNT_HINTS.search(table_or_path):
        return "account_change"
    if _PII_HINTS.search(table_or_path):
        return "data_access"
    return "other"


def _iter_sql_strings(call: ast.Call) -> Iterator[tuple[int, str]]:
    """Yield (lineno, string) for any SQL-ish string reachable as an arg of
    `call`. Includes direct string literals, single-level wrappers like
    `text("UPDATE …")`, and the constant prefix of f-strings. Deliberately
    skips strings that are not being passed to a call — that's what kills
    the module-level-constant / docstring / comment false positives."""
    args: list[ast.expr] = list(call.args) + [kw.value for kw in call.keywords]
    for arg in args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            yield (arg.lineno, arg.value)
        elif isinstance(arg, ast.Call):
            # Wrapper like sqlalchemy.text("UPDATE ..."). Recurse one level.
            for sub in arg.args:
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    yield (sub.lineno, sub.value)
        elif isinstance(arg, ast.JoinedStr):
            # f-string — scan only the constant prefix / interleaved literals.
            parts = "".join(
                v.value for v in arg.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if parts:
                yield (arg.lineno, parts)


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = safe_read(path)
        if text is None:
            continue
        tree = parse_python(text)
        if tree is None:
            continue

        # Raw SQL — look only inside Call arguments. Immune to comments,
        # docstrings, and standalone module-level string constants.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for lineno, s in _iter_sql_strings(node):
                for pattern, verb in (
                    (_PY_SQL_UPDATE, "UPDATE"),
                    (_PY_SQL_DELETE, "DELETE"),
                    (_PY_SQL_INSERT, "INSERT"),
                ):
                    m = pattern.search(s)
                    if not m:
                        continue
                    table = m.group(1)
                    findings.append(Finding(
                        scanner="db-mutations",
                        file=str(path),
                        line=lineno,
                        snippet=m.group(0),
                        suggested_action_type=_suggest(table),
                        confidence="medium",
                        rationale=f"Raw SQL {verb} on `{table}`. Gate with {_suggest(table)} policy if state-changing.",
                        extra={"verb": verb, "table": table},
                    ))
                    break  # one verb per arg

        # ORM mutations: flag only when the file both mutates and commits.
        # Still regex — it's a file-level heuristic, not a line-level claim,
        # and the same text-search property is fine (commits/mutates are
        # identifier-anchored so comment FPs are rare).
        has_commit = bool(_PY_COMMIT.search(text))
        if has_commit:
            for m in _PY_SESSION_MUTATE.finditer(text):
                line = text[: m.start()].count("\n") + 1
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type=_suggest(str(path)),
                    confidence="low",
                    rationale="SQLAlchemy session mutation + commit in the same file. "
                              "Confirm whether the mutation should be supervised.",
                    extra={"op": m.group(1)},
                ))
    return findings


def _scan_ts_js(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in ts_js_files(root):
        text = safe_read(path)
        if text is None:
            continue
        for m in _TS_PRISMA.finditer(text):
            line = text[: m.start()].count("\n") + 1
            model = m.group(1)
            op = m.group(2)
            findings.append(Finding(
                scanner="db-mutations",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type=_suggest(model),
                confidence="high",
                rationale=f"Prisma {op} on model `{model}` — state-changing, gate with an appropriate policy.",
                extra={"orm": "prisma", "model": model, "op": op},
            ))
        for pattern, verb in (
            (_TS_SQL_UPDATE, "UPDATE"),
            (_TS_SQL_DELETE, "DELETE"),
            (_TS_SQL_INSERT, "INSERT"),
        ):
            for m in pattern.finditer(text):
                line = text[: m.start()].count("\n") + 1
                table = m.group(1)
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type=_suggest(table),
                    confidence="medium",
                    rationale=f"Raw SQL {verb} on `{table}`.",
                    extra={"verb": verb, "table": table},
                ))
    return findings


def scan(root: Path) -> list[Finding]:
    return _scan_python(root) + _scan_ts_js(root)
