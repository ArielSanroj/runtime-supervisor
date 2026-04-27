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
from ._utils import parse_python, python_files, safe_read, sql_files, ts_js_files

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

# Supabase JS pattern: `<client>.from('table').{upsert,update,delete,insert}(`.
# The chain shape is unique enough to not collide with array.from / drizzle's
# `.from()` (which doesn't terminate in upsert/update/delete/insert calls).
_TS_SUPABASE_MUTATION = re.compile(
    r"""\.from\(\s*['"](\w+)['"]\s*\)\s*\.(upsert|update|delete|insert)\s*\(""",
)
_TS_SUPABASE_IMPORT = re.compile(r"""['"]@supabase/supabase-js['"]""")
# Service-role hint: when the same module references `SERVICE_ROLE_KEY` (or
# any casing variant) the dev knowingly chose admin privileges over RLS. The
# write itself isn't a bug — the chokepoint is that every write from this
# module bypasses row-level policies, so a mis-routed table or `id` argument
# rewrites the whole table without the per-row guard.
_TS_SERVICE_ROLE_HINT = re.compile(
    r"""SERVICE_ROLE_KEY|service_role_key|serviceRoleKey""",
)

# Redis cache wipes — `flushall` clears every database, `flushdb` clears the
# current one. Both are nearly always operational scripts in production code
# and almost never used inside an LLM-driven path; surfacing them at high
# confidence would produce noise. Medium is the right tier — a flag, not a
# fire alarm. Match by method-name suffix so we cover redis-py (`r.flushall()`),
# aioredis (`await client.flushall()`), and ioredis on TS (`await redis.flushdb()`).
_REDIS_FLUSH_METHODS = frozenset({"flushall", "flushdb"})
_TS_REDIS_FLUSH = re.compile(r"\.(flushall|flushdb)\s*\(", re.IGNORECASE)


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

        # Redis cache wipes — `client.flushall()` / `client.flushdb()`.
        # AST-only so we can't trip on the strings "flushall" inside docs.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _REDIS_FLUSH_METHODS
            ):
                continue
            line = node.lineno
            method = node.func.attr
            findings.append(Finding(
                scanner="db-mutations",
                file=str(path),
                line=line,
                snippet=f"{method}(",
                suggested_action_type="data_access",
                confidence="medium",
                rationale=(
                    f"Redis `{method}()` wipes a whole keyspace. Inside an "
                    "agent loop this is data loss with no rollback — wrap "
                    "with @supervised('data_access') and require an explicit "
                    "operator confirmation."
                ),
                extra={"verb": "FLUSH", "family": "redis-flush", "method": method},
            ))

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
        # Supabase JS writes. Only emit when the file imports the SDK or the
        # call shape unambiguously matches — otherwise we'd flag any drizzle
        # / kysely / array `.from()` chain. Service-role presence promotes
        # the finding to high confidence with an RLS-bypass rationale.
        is_supabase_module = bool(
            _TS_SUPABASE_IMPORT.search(text) or _TS_SUPABASE_MUTATION.search(text)
        )
        if is_supabase_module:
            service_role = bool(_TS_SERVICE_ROLE_HINT.search(text))
            for m in _TS_SUPABASE_MUTATION.finditer(text):
                line = text[: m.start()].count("\n") + 1
                table = m.group(1)
                op = m.group(2).lower()
                if service_role:
                    rationale = (
                        f"Supabase `{op}` on `{table}` from a module that "
                        "uses the service-role key — RLS is bypassed by "
                        "design. If the table or row id ever comes from "
                        "user / agent input, every row in `"
                        f"{table}` is writable. Wrap and pin the table "
                        "name plus the predicate to a fixed allowlist."
                    )
                    confidence = "high"
                else:
                    rationale = (
                        f"Supabase `{op}` on `{table}`. RLS still enforces "
                        "per-row policies, but confirm the calling code "
                        "isn't running with the service-role key in "
                        "another path."
                    )
                    confidence = "medium"
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0).rstrip("("),
                    suggested_action_type=_suggest(table),
                    confidence=confidence,
                    rationale=rationale,
                    extra={
                        "orm": "supabase-js",
                        "table": table,
                        "op": op,
                        "service_role": service_role,
                    },
                ))

        # Redis cache wipes — same method name across redis-py and ioredis.
        for m in _TS_REDIS_FLUSH.finditer(text):
            line = text[: m.start()].count("\n") + 1
            method = m.group(1).lower()
            findings.append(Finding(
                scanner="db-mutations",
                file=str(path),
                line=line,
                snippet=m.group(0).rstrip("("),
                suggested_action_type="data_access",
                confidence="medium",
                rationale=(
                    f"Redis `{method}()` wipes a whole keyspace. Inside an "
                    "agent loop this is data loss with no rollback — wrap and "
                    "require an explicit operator confirmation."
                ),
                extra={"verb": "FLUSH", "family": "redis-flush", "method": method},
            ))
    return findings


# SQL line-comment / block-comment strippers. We discard comment text
# before regex matching so prose like `-- UPDATE the ad campaign` doesn't
# fire the UPDATE detector. Block-comment stripper is non-greedy across
# newlines.
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)

# Postgres / Supabase RLS markers. The detector cares about three statements:
#   - CREATE TABLE x (...)                      — declares a table.
#   - ALTER TABLE x ENABLE ROW LEVEL SECURITY   — turns on per-row policies.
#   - CREATE POLICY name ON x FOR ...           — adds an actual rule.
# A table created without an `enable row level security` is open to the
# anon key (Supabase) — usually wrong. A table with RLS but no policy
# blocks every non-service-role caller — usually intentional but worth
# flagging so the dev confirms.
_SQL_CREATE_TABLE = re.compile(
    r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?(\w+)",
    re.IGNORECASE,
)
_SQL_ENABLE_RLS = re.compile(
    r"\balter\s+table\s+(?:public\.)?(\w+)\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
# Policy names are arbitrary text — quoted (with dashes, dots, spaces) or
# bare identifiers. Match any chars on the same statement line until ` ON
# <table>`. The non-greedy `[^\n]*?` keeps us inside one statement.
_SQL_CREATE_POLICY = re.compile(
    r"""\bcreate\s+policy\b[^\n]*?\son\s+(?:public\.)?(\w+)""",
    re.IGNORECASE,
)

# RLS is a Postgres / Supabase concept. Plain SQLite schemas often look like
# small app schemas (`CREATE TABLE leads ...`) and should not be flagged as
# missing RLS. Gate the RLS audit on dialect/path evidence so raw SQL mutation
# detection still runs everywhere, but DDL policy advice stays stack-specific.
_SQLITE_DIALECT_HINT = re.compile(
    r"""\bPRAGMA\b|\bAUTOINCREMENT\b|\bINTEGER\s+PRIMARY\s+KEY\b|\bsqlite_\w+|\bWITHOUT\s+ROWID\b""",
    re.IGNORECASE,
)
_POSTGRES_RLS_CONTEXT_HINT = re.compile(
    r"""
    \benable\s+row\s+level\s+security\b
    |\bcreate\s+policy\b
    |\bpublic\.
    |\bauth\.users\b
    |\bjsonb\b
    |\bbigserial\b
    |\bserial\b
    |\buuid\b
    |\btimestamptz\b
    |\bgen_random_uuid\s*\(
    |\buuid_generate_v4\s*\(
    |\bcreate\s+extension\b
    |\blanguage\s+plpgsql\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
_POSTGRES_PATH_HINTS = {"supabase", "postgres", "postgresql", "postgrest"}


def _strip_sql_comments(text: str) -> str:
    """Replace SQL comments with same-length whitespace so byte offsets
    stay valid. Keeps line numbers correct for the regex match below."""
    def _blank(match: "re.Match[str]") -> str:
        # Preserve newlines so `text[:start].count("\n")` still gives the
        # correct line number for non-comment matches that follow.
        return "".join(c if c == "\n" else " " for c in match.group(0))
    cleaned = _SQL_BLOCK_COMMENT.sub(_blank, text)
    cleaned = _SQL_LINE_COMMENT.sub(_blank, cleaned)
    return cleaned


def _path_suggests_postgres(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return any(part.lower() in _POSTGRES_PATH_HINTS for part in rel.parts)


def _should_run_rls_audit(path: Path, root: Path, cleaned_sql: str) -> bool:
    if _SQLITE_DIALECT_HINT.search(cleaned_sql):
        return False
    return (
        bool(_POSTGRES_RLS_CONTEXT_HINT.search(cleaned_sql))
        or _path_suggests_postgres(path, root)
    )


def _scan_sql_files(root: Path) -> list[Finding]:
    """Detect raw INSERT / UPDATE / DELETE statements in `*.sql` files.

    Why we need this: `aiosql.from_path(...)` and equivalent loaders pull
    SQL bodies from disk, so the Python scanner only sees the loader call
    and never reaches the mutations themselves. fastapi-realworld is the
    canonical case — `app/db/queries/sql/articles.sql` runs `UPDATE
    articles SET …` and the scan reported zero `db-mutations`.

    Confidence is `medium` because we don't have caller context (same as
    raw SQL strings inside Python source). Severity (`account_change` /
    `data_access` / `other`) comes from the table name via `_suggest()`,
    matching the Python and TS code paths.

    Comments (`--` and `/* … */`) are stripped before matching so prose
    like `-- TODO: UPDATE the schema` doesn't fire."""
    findings: list[Finding] = []
    for path in sql_files(root):
        text = safe_read(path)
        if text is None:
            continue
        cleaned = _strip_sql_comments(text)
        for pattern, verb in (
            (_PY_SQL_UPDATE, "UPDATE"),
            (_PY_SQL_DELETE, "DELETE"),
            (_PY_SQL_INSERT, "INSERT"),
        ):
            for m in pattern.finditer(cleaned):
                line = cleaned[: m.start()].count("\n") + 1
                table = m.group(1)
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type=_suggest(table),
                    confidence="medium",
                    rationale=(
                        f"Raw SQL {verb} on `{table}` in a .sql file "
                        "loaded at runtime (e.g. via aiosql / asyncpg "
                        "from_path). Gate the loader's caller with the "
                        f"{_suggest(table)} policy if state-changing."
                    ),
                    extra={
                        "verb": verb,
                        "table": table,
                        "source_kind": "sql-file",
                    },
                ))
    return findings


def _scan_sql_rls(root: Path) -> list[Finding]:
    """Per-table RLS audit on `*.sql` migration files.

    Emits one finding per table that the file creates without an
    accompanying `alter table … enable row level security`. With the
    `--include-migrations` flag this turns the otherwise-mute SQL DDL
    into actionable signal — Supabase apps that forget RLS leak data
    by default the moment the anon key is shared in the frontend.

    The check is per-file: if a table is declared in `init.sql` and a
    later migration enables RLS on it, the later file shows the table
    as RLS-enabled. The same table reported as missing-RLS in the
    earlier file remains visible — that history is real signal, not a
    bug — and the dev decides whether to suppress it via
    `.supervisor-ignore`.
    """
    findings: list[Finding] = []
    for path in sql_files(root):
        text = safe_read(path)
        if text is None:
            continue
        cleaned = _strip_sql_comments(text)
        if not _should_run_rls_audit(path, root, cleaned):
            continue

        rls_tables = {m.group(1).lower() for m in _SQL_ENABLE_RLS.finditer(cleaned)}
        policy_tables = {
            m.group(1).lower() for m in _SQL_CREATE_POLICY.finditer(cleaned)
        }

        for m in _SQL_CREATE_TABLE.finditer(cleaned):
            table = m.group(1)
            line = cleaned[: m.start()].count("\n") + 1
            table_lower = table.lower()

            if table_lower not in rls_tables:
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type=_suggest(table),
                    # `medium`, not `high`: the rule is accurate but lives
                    # outside the agent-supervision charter ("unsafe call-
                    # sites your LLM can fire"). At `high` it dominated
                    # the headline on pre-agent Supabase repos (tph
                    # benchmark — 3 RLS findings, 0 wrap targets) and
                    # made the report look like an agent-risk audit when
                    # it wasn't.
                    confidence="medium",
                    rationale=(
                        f"Table `{table}` is created without "
                        "`alter table … enable row level security`. On "
                        "Supabase / Postgres-with-PostgREST stacks, the "
                        "anon key gets full access to every column the "
                        "moment that key ships to the frontend. Add the "
                        "RLS toggle and at least one policy."
                    ),
                    extra={
                        "verb": "RLS_MISSING",
                        "table": table,
                        "family": "rls-missing",
                        "source_kind": "sql-file",
                        # Routes this finding into RepoSummary.database_hygiene
                        # instead of real_world_actions / top_risks — keeps
                        # the agent-supervision headline focused on wrap-
                        # points the LLM can actually fire.
                        "scope": "non-agent-security",
                    },
                ))
                continue

            if table_lower not in policy_tables:
                findings.append(Finding(
                    scanner="db-mutations",
                    file=str(path),
                    line=line,
                    snippet=m.group(0),
                    suggested_action_type=_suggest(table),
                    confidence="medium",
                    rationale=(
                        f"Table `{table}` has RLS enabled but no "
                        "`create policy` is declared in this file. The "
                        "anon key is locked out by default — confirm "
                        "that's intentional and not a forgotten rule. "
                        "Service-role calls still bypass RLS."
                    ),
                    extra={
                        "verb": "RLS_NO_POLICY",
                        "table": table,
                        "family": "rls-no-policy",
                        "source_kind": "sql-file",
                        "scope": "non-agent-security",
                    },
                ))
    return findings


def scan(root: Path) -> list[Finding]:
    return (
        _scan_python(root)
        + _scan_ts_js(root)
        + _scan_sql_files(root)
        + _scan_sql_rls(root)
    )
