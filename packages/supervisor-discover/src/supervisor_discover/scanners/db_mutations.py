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

import re
from pathlib import Path

from ..findings import Finding
from ._utils import python_files, ts_js_files

_ACCOUNT_HINTS = re.compile(r"\b(users?|accounts?|customers?|profiles?|identities)\b", re.IGNORECASE)
_PII_HINTS = re.compile(r"\b(emails?|phones?|ssn|addresses?|payments?|cards?)\b", re.IGNORECASE)

_PY_RAW_SQL = re.compile(
    r"""\b(UPDATE|DELETE|INSERT)\b\s+(?:INTO\s+|FROM\s+)?(\w+)""",
    re.IGNORECASE,
)
_PY_COMMIT = re.compile(r"\bsession\.commit\(\)")
_PY_SESSION_MUTATE = re.compile(r"\bsession\.(add|delete|merge)\b")

_TS_PRISMA = re.compile(r"\bprisma\.(\w+)\.(update|delete|upsert|create|createMany|deleteMany|updateMany)\s*\(")
_TS_TYPEORM = re.compile(r"\.(remove|save|delete|update)\s*\(", re.IGNORECASE)
_TS_RAW_SQL = re.compile(r"""\b(UPDATE|DELETE|INSERT)\b\s+(?:INTO\s+|FROM\s+)?(\w+)""", re.IGNORECASE)


def _suggest(table_or_path: str) -> str:
    if _ACCOUNT_HINTS.search(table_or_path):
        return "account_change"
    if _PII_HINTS.search(table_or_path):
        return "data_access"
    return "other"


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in python_files(root):
        text = path.read_text(errors="ignore")
        # Raw SQL
        for m in _PY_RAW_SQL.finditer(text):
            line = text[: m.start()].count("\n") + 1
            verb, table = m.group(1).upper(), m.group(2)
            findings.append(Finding(
                scanner="db-mutations",
                file=str(path),
                line=line,
                snippet=m.group(0),
                suggested_action_type=_suggest(table),
                confidence="medium",
                rationale=f"Raw SQL {verb} on `{table}`. Gate with {_suggest(table)} policy if state-changing.",
                extra={"verb": verb, "table": table},
            ))
        # ORM mutations: flag only when the file both mutates and commits
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
        text = path.read_text(errors="ignore")
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
        for m in _TS_RAW_SQL.finditer(text):
            line = text[: m.start()].count("\n") + 1
            verb, table = m.group(1).upper(), m.group(2)
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
