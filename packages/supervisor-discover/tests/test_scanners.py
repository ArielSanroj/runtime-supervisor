from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners._utils import python_files

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"
NEXT_FIXTURE = Path(__file__).parent / "fixtures/fake_next_app"
VERCEL_SAAS_FIXTURE = Path(__file__).parent / "fixtures/fake_vercel_saas"
TRAP_FIXTURE = Path(__file__).parent / "fixtures/adversarial_trap"


def _by_scanner(findings):
    buckets: dict[str, list] = {}
    for f in findings:
        buckets.setdefault(f.scanner, []).append(f)
    return buckets


def test_flask_fixture_finds_stripe_refund_as_refund_action():
    findings = scan_all(FLASK_FIXTURE)
    payments = [f for f in findings if f.scanner == "payment-calls"]
    # Both app.py (literal `stripe.*`) and aliased.py (`_stripe.*`) should match.
    assert len(payments) >= 1
    refund_in_app = next((f for f in payments if "app.py" in f.file), None)
    assert refund_in_app is not None
    assert refund_in_app.suggested_action_type == "refund"
    assert refund_in_app.confidence == "high"
    assert "stripe.Refund.create" in refund_in_app.snippet


def test_flask_fixture_finds_openai_as_tool_use():
    findings = scan_all(FLASK_FIXTURE)
    llms = [f for f in findings if f.scanner == "llm-calls"]
    assert len(llms) >= 1
    assert all(f.suggested_action_type == "tool_use" for f in llms)


def test_flask_fixture_finds_http_routes():
    findings = scan_all(FLASK_FIXTURE)
    routes = [f for f in findings if f.scanner == "http-routes"]
    # Two @app.route decorators
    assert len(routes) == 2


def test_http_routes_point_at_decorator_line_not_function_body():
    """Regression: `line` must land on the `@app.route(...)` line so that
    file:line in the UI highlights the decorator. Previously it pointed
    at the `def fn():` line below it, which is useless for review."""
    findings = scan_all(FLASK_FIXTURE)
    routes = [f for f in findings if f.scanner == "http-routes"]
    src = (FLASK_FIXTURE / "app.py").read_text().splitlines()
    for f in routes:
        if "app.py" not in f.file:
            continue
        real = src[f.line - 1]
        assert "@app.route" in real, (
            f"http-routes finding at line {f.line} should be on a decorator, "
            f"got {real!r}. Snippet reported: {f.snippet!r}"
        )


def test_self_check_drops_finding_whose_snippet_is_missing_from_line(tmp_path):
    """Layer-2 defense: scan_all must refuse to return a finding whose
    reported snippet doesn't actually appear on the reported line.

    Simulates a detector that reports `plan_tool.py:8 AGENT CHOKEPOINT`
    with `snippet='def plan('` — but line 8 is a comment. The self-check
    drops it so the UI never sees it."""
    from supervisor_discover.findings import Finding
    from supervisor_discover.scanners import _self_check

    f = tmp_path / "plan_tool.py"
    f.write_text(
        '"""docs"""\n'        # 1
        '\n'                  # 2
        'import os\n'         # 3
        '\n'                  # 4
        '# storage of plan\n' # 5 — has the word "plan" but no `def`
        '\n'                  # 6
        'class Foo: pass\n'   # 7
        '    # plan (raw)\n'  # 8 — a comment that literally says "plan ("
    )

    bad = Finding(
        scanner="agent-orchestrators", file=str(f), line=8,
        snippet="def plan(",  # NOT on line 8 — line 8 is a comment
        suggested_action_type="tool_use", confidence="high", rationale="bad",
    )
    good = Finding(
        scanner="other-test", file=str(f), line=3,
        snippet="import os",   # really on line 3
        suggested_action_type="other", confidence="high", rationale="ok",
    )
    cleaned = _self_check([bad, good])
    assert good in cleaned, "self-check must keep findings that do match the line"
    assert bad not in cleaned, (
        "self-check must drop findings whose snippet is absent from the reported line"
    )


def test_self_check_tolerates_synthetic_comment_suffix_in_snippet():
    """http-routes snippets look like `@app.get  # my_handler` — the `# my_handler`
    is synthetic UI context, not real code. The self-check must probe only the
    real prefix and still accept the finding."""
    from supervisor_discover.scanners import _snippet_matches_line

    # Real decorator line in the repo.
    real = '@app.get("/api")'
    # Synthetic snippet built by http_routes.py.
    synth_snippet = '@app.get  # api_root'

    assert _snippet_matches_line(synth_snippet, real), (
        "prefix before `#` must be compared, not the synthetic suffix"
    )


def test_self_check_drops_finding_on_out_of_range_line(tmp_path):
    """A scanner that reports a line past the file end (drift after the scan)
    must have the finding dropped, not blow up with IndexError."""
    from supervisor_discover.findings import Finding
    from supervisor_discover.scanners import _self_check

    f = tmp_path / "short.py"
    f.write_text("x = 1\n")  # 1 line total

    bogus = Finding(
        scanner="x", file=str(f), line=999,
        snippet="whatever", suggested_action_type="other",
        confidence="high", rationale="rot",
    )
    assert _self_check([bogus]) == []


def test_adversarial_trap_produces_one_true_positive_and_no_false_positives():
    """Capa 1 regression: scan a fixture packed with keywords hidden in
    comments, docstrings, string literals, f-strings, and regex patterns.
    The only finding allowed is the single real `subprocess.run(...)` call
    at line 60. Any other finding means a scanner is treating non-code as
    code.

    File is `tests/fixtures/adversarial_trap/traps.py`. Line references in
    this test must stay in sync with that file."""
    from supervisor_discover.scanners import scan_all
    findings = scan_all(TRAP_FIXTURE)
    assert len(findings) == 1, (
        f"adversarial trap must produce exactly 1 finding (the real "
        f"subprocess.run at L75). Got {len(findings)}: "
        f"{[(f.scanner, f.line, f.snippet) for f in findings]}"
    )
    only = findings[0]
    assert only.scanner == "fs-shell"
    assert only.line == 75
    assert "subprocess.run" in only.snippet
    assert only.extra.get("family") == "shell-exec"


def test_agent_method_in_agent_path_is_high_confidence(tmp_path):
    """Capa 5 gate: agent-method findings only fire inside agent paths, and
    when they do they're as load-bearing as agent-class hits. Both must be
    `high` so the public UI (which filters to high) still shows the chokepoints
    — that's the killer demo feature and it lives on agent-method detection."""
    from supervisor_discover.scanners import scan_all

    repo = tmp_path / "repo" / "agent" / "tools"
    repo.mkdir(parents=True)
    (repo / "foo.py").write_text(
        "class Foo:\n"
        "    async def execute(self):\n"
        "        return 1\n"
    )

    findings = scan_all(tmp_path / "repo")
    method = next(
        (f for f in findings
         if f.scanner == "agent-orchestrators"
         and f.extra.get("kind") == "agent-method"),
        None,
    )
    assert method is not None, (
        f"agent-method not detected in agent path. All findings: {findings!r}"
    )
    assert method.confidence == "high", (
        f"agent-method inside an agent path should be high confidence "
        f"(consistent with agent-class rule). Got {method.confidence!r}."
    )


def test_ast_method_detection_ignores_non_code_contexts(tmp_path):
    """Layer-3 defense: Python method detection uses AST, so the scanner
    is immune to word-matches inside comments, docstrings, f-strings, or
    call sites. Only real `def` / `async def` nodes fire."""
    from supervisor_discover.scanners import scan_all

    repo = tmp_path / "trap" / "agent" / "tools"
    repo.mkdir(parents=True)
    (repo / "plan_tool.py").write_text(
        '"""Module docstring — plan (should be ignored).\n'
        '\n'
        'Talks about execute() and dispatch() in prose.\n'
        '"""\n'
        '# In-memory storage for the current plan (raw structure)\n'   # L5 — comment
        'from typing import Any\n'                                       # L6
        '\n'                                                             # L7
        'NOTE = "plan(foo)"  # string literal\n'                         # L8 — string
        'MSG = f"time to execute({NOTE})"  # f-string\n'                 # L9 — f-string
        '\n'                                                             # L10
        '\n'                                                             # L11
        'class PlanTool:\n'                                              # L12
        '    async def execute(self, params: Any) -> Any:\n'             # L13 ← real def
        '        self.plan(params)  # call site — should NOT fire\n'     # L14
        '        return params\n'                                        # L15
        '\n'                                                             # L16
        '    def plan(self, params: Any) -> Any:\n'                      # L17 ← real def
        '        return params\n'                                        # L18
    )

    findings = scan_all(tmp_path / "trap")
    methods = [f for f in findings if f.scanner == "agent-orchestrators"
               and f.extra.get("kind") == "agent-method"]

    # Must fire on real defs at L13 (execute) and L17 (plan).
    lines_hit = sorted(f.line for f in methods)
    assert 13 in lines_hit, f"missed real `async def execute(` at L13; got {lines_hit}"
    assert 17 in lines_hit, f"missed real `def plan(` at L17; got {lines_hit}"

    # Must NOT fire on any non-code line.
    forbidden_lines = {1, 3, 5, 8, 9, 14}  # docstring, comment, strings, call-site
    leaked = [f for f in methods if f.line in forbidden_lines]
    assert not leaked, (
        f"agent-orchestrators leaked into non-code context. "
        f"Offending findings: {[(f.line, f.snippet) for f in leaked]}"
    )


def test_ast_method_detection_tolerates_syntax_errors(tmp_path):
    """If a Python file has a syntax error, ast.parse raises. The scanner
    must skip the file silently instead of crashing the whole scan."""
    from supervisor_discover.scanners import scan_all

    repo = tmp_path / "brokenrepo" / "agent" / "tools"
    repo.mkdir(parents=True)
    (repo / "broken.py").write_text(
        "def execute(  # unterminated — AST can't parse\n"
    )
    (repo / "ok.py").write_text(
        "class Foo:\n"
        "    async def execute(self):\n"
        "        return 1\n"
    )

    # Must not raise. The broken file contributes zero method findings;
    # the ok file still contributes one.
    findings = scan_all(tmp_path / "brokenrepo")
    methods = [f for f in findings if f.scanner == "agent-orchestrators"
               and f.extra.get("kind") == "agent-method"]
    from_broken = [f for f in methods if "broken.py" in f.file]
    from_ok = [f for f in methods if "ok.py" in f.file]
    # The class `Foo` would fire as a class-hit AND dedupe the method within 10 lines;
    # but `Foo` doesn't match the agent-class name regex, so the class hit won't fire,
    # which means the method at line 2 of ok.py DOES fire.
    assert not from_broken
    assert any(f.line == 2 for f in from_ok), f"ok.py method missed: {from_ok}"


def test_agent_method_regex_ignores_word_in_comments(tmp_path):
    """Regression: the method-name regex previously had `(?:def|function)?`
    with an optional group, which matched `plan (` anywhere — including
    in comments like `# In-memory storage for the current plan (...)`.
    The fix makes `def|function` required."""
    from supervisor_discover.scanners import scan_all

    repo = tmp_path / "my_repo" / "agent" / "tools"
    repo.mkdir(parents=True)
    (repo / "plan_tool.py").write_text(
        '"""Tool for managing a plan."""\n'
        'from typing import Any\n'
        '\n'
        '# In-memory storage for the current plan (raw structure from agent)\n'
        '_current_plan: list = []\n'
        '\n'
        'class PlanTool:\n'
        '    async def execute(self, params: Any) -> Any:\n'
        '        return _current_plan\n'
    )

    findings = scan_all(tmp_path / "my_repo")
    ao = [f for f in findings if f.scanner == "agent-orchestrators"]
    # Must NOT fire on the comment line (" plan (raw ...").
    in_comments = [f for f in ao if f.line == 4]
    assert not in_comments, (
        f"agent-orchestrators fired on a comment line: {[f.snippet for f in in_comments]!r}"
    )
    # Must still fire on the real `async def execute(` definition at line 8.
    real_methods = [f for f in ao if f.line == 8 and f.extra.get("method_name") == "execute"]
    assert real_methods, (
        f"agent-orchestrators missed the real `async def execute(` chokepoint. "
        f"All findings: {[(f.line, f.extra) for f in ao]!r}"
    )


def test_training_paths_get_downgraded(tmp_path: Path):
    """Files under training/ should have their confidence downgraded one step.
    A subprocess.run in training/run.py should land at `medium`, not `high`,
    so the free-tier high-confidence gate hides it as research noise."""
    (tmp_path / "training").mkdir()
    (tmp_path / "training" / "run.py").write_text(
        "import subprocess\n"
        "subprocess.run(args)\n"  # variable args so snippet refinement keeps high
    )
    findings = scan_all(tmp_path)
    sub = [f for f in findings if f.scanner == "fs-shell"]
    assert sub, "expected at least one fs-shell finding from training/run.py"
    assert all(f.confidence != "high" for f in sub), (
        f"training/ paths must downgrade — got {[(f.file, f.confidence) for f in sub]}"
    )
    assert all(f.extra.get("downgraded_eval_path") for f in sub)


def test_ts_construction_fires_without_method_call(tmp_path: Path):
    """`new OpenAI()` alone is an LLM signal even if no .create method is
    called in the same file. The wrapping module is the call-site to gate.

    Construction findings are rated `low` — there's no prompt at the
    constructor, so wrapping it gates nothing. The actual chokepoint is the
    `.create()` / `generateText()` call elsewhere. Keeping the construction
    finding visible in FULL_REPORT but out of the public scan's
    high-confidence top is the point of the downgrade.
    """
    (tmp_path / "client.ts").write_text(
        'import OpenAI from "openai";\n'
        "const c = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n"
        "export default c;\n"
    )
    findings = scan_all(tmp_path)
    llm = [f for f in findings if f.scanner == "llm-calls"]
    assert llm, "expected llm-calls to fire on `new OpenAI()`"
    construction = [f for f in llm if f.extra.get("kind") == "construction"]
    assert construction
    assert all(f.confidence == "low" for f in construction), (
        f"constructor without prompt must be rated low, got "
        f"{[f.confidence for f in construction]}"
    )


def test_python_constructor_low_confidence_invocation_high(tmp_path: Path):
    """`openai.OpenAI(api_key=...)` constructs a client (no prompt yet) and
    must be rated `low`. The follow-up `client.chat.completions.create(...)`
    has the prompt and stays `high`. Mixing both in one finding tier inflates
    the high-confidence count and was the user-visible bug on the langchain
    free scan output."""
    (tmp_path / "moderation.py").write_text(
        "import openai\n"
        "\n"
        "client = openai.OpenAI(api_key='sk-x')\n"
        "\n"
        "def moderate(prompt):\n"
        "    return openai.chat.completions.create(model='gpt-4o', messages=[{'role':'user','content':prompt}])\n"
    )
    findings = scan_all(tmp_path)
    llm = [f for f in findings if f.scanner == "llm-calls"]
    by_kind = {f.extra.get("kind"): f for f in llm}
    assert "construction" in by_kind, f"expected construction finding, got {[(f.snippet, f.extra) for f in llm]}"
    assert "invocation" in by_kind, f"expected invocation finding, got {[(f.snippet, f.extra) for f in llm]}"
    assert by_kind["construction"].confidence == "low"
    assert by_kind["invocation"].confidence == "high"


def test_ts_vercel_ai_sdk_generate_text_fires(tmp_path: Path):
    """Vercel AI SDK uses `generateText` from `"ai"` — the original detector
    didn't know about it, so voicebox/multica scored 0 LLM findings."""
    (tmp_path / "page.ts").write_text(
        'import { generateText } from "ai";\n'
        'const r = await generateText({ model, prompt: input });\n'
    )
    findings = scan_all(tmp_path)
    llm = [f for f in findings if f.scanner == "llm-calls"]
    assert llm, "expected llm-calls to fire on Vercel AI SDK generateText()"
    assert any("generateText" in f.snippet for f in llm)


def test_orchestrator_excludes_webview_tests_and_build_paths():
    """Webview scripts, test trees, and build outputs may pattern-match the
    agent-orchestrator regex (Controller / Dispatcher / handle / dispatch),
    but they don't run real agent code in production. They must be filtered."""
    from supervisor_discover.scanners.agent_orchestrators import _is_excluded_path

    excluded = [
        "packages/vscode-extension/src/webview/scripts/semanticSearch.js",
        "apps/foo/__tests__/orchestrator.test.ts",
        "apps/foo/tests/test_dispatcher.py",
        "packages/foo/e2e/agent.spec.ts",
        "node_modules/some-pkg/src/agent.js",
        "apps/foo/dist/orchestrator.js",
        "apps/foo/.next/server/agent.js",
        "apps/foo/coverage/Controller.js",
        "examples/agent-demo/Controller.py",
        "src/api/orchestrator.test.py",
        "src/api/orchestrator.spec.ts",
    ]
    for p in excluded:
        assert _is_excluded_path(p), f"expected {p} to be excluded"

    included = [
        "src/orchestrator/Controller.py",
        "apps/api/agents/dispatcher.ts",
        "packages/core/src/agent/Planner.ts",
        "services/api/src/Controller.py",
    ]
    for p in included:
        assert not _is_excluded_path(p), f"expected {p} to be included"


def test_flask_fixture_finds_raw_sql_update_on_users():
    findings = scan_all(FLASK_FIXTURE)
    mutations = [f for f in findings if f.scanner == "db-mutations"]
    update = next((f for f in mutations if f.extra.get("verb") == "UPDATE"), None)
    assert update is not None
    assert update.extra["table"] == "users"
    assert update.suggested_action_type == "account_change"


def test_next_fixture_finds_stripe_refund():
    findings = scan_all(NEXT_FIXTURE)
    payments = [f for f in findings if f.scanner == "payment-calls"]
    assert len(payments) == 1
    assert payments[0].suggested_action_type == "refund"


def test_next_fixture_finds_openai():
    findings = scan_all(NEXT_FIXTURE)
    llms = [f for f in findings if f.scanner == "llm-calls"]
    assert len(llms) >= 1


def test_next_fixture_finds_api_route():
    findings = scan_all(NEXT_FIXTURE)
    routes = [f for f in findings if f.scanner == "http-routes"]
    assert any("POST" in f.extra.get("method", "") for f in routes)


# ─── fake_vercel_saas: Stripe Checkout + Supabase service-role + server actions ─
#
# This fixture mirrors the surfaces in `vercel/nextjs-subscription-payments` —
# the canonical "SaaS without an LLM" template. Every assertion below is a
# pattern the scanner used to miss against the real repo (3 informational
# findings, "no payment SDKs detected") and now catches.


def test_vercel_saas_finds_stripe_checkout_session_create():
    findings = scan_all(VERCEL_SAAS_FIXTURE)
    payments = [f for f in findings if f.scanner == "payment-calls"]
    methods = {f.extra.get("method", f.snippet) for f in payments}
    assert any("checkout.sessions.create" in m for m in methods)
    assert any("billingPortal.sessions.create" in m for m in methods)
    assert any("subscriptions.cancel" in m for m in methods)
    assert all(p.confidence == "high" for p in payments)
    assert all(p.suggested_action_type == "payment" for p in payments)


def test_vercel_saas_supabase_service_role_is_high_confidence():
    findings = scan_all(VERCEL_SAAS_FIXTURE)
    sb = [f for f in findings
          if f.scanner == "db-mutations"
          and f.extra.get("orm") == "supabase-js"]
    assert len(sb) >= 3
    assert all(f.confidence == "high" for f in sb), (
        "service-role + Supabase mutation must be high confidence"
    )
    assert all(f.extra.get("service_role") is True for f in sb)
    tables = {f.extra.get("table") for f in sb}
    assert {"customers", "users", "subscriptions"} <= tables


def test_vercel_saas_server_action_directive_emits_handlers():
    findings = scan_all(VERCEL_SAAS_FIXTURE)
    actions = [f for f in findings
               if f.scanner == "http-routes"
               and f.extra.get("framework") == "next-server-action"]
    fn_names = {f.extra.get("function") for f in actions}
    assert {"checkoutWithStripe", "createPortalSession", "cancelSubscription"} <= fn_names
    assert all(f.confidence == "high" for f in actions)


def test_vercel_saas_emits_webhook_idempotency_combo():
    """Webhook handler + DB writes triggers the idempotency combo. The
    handler in the fixture verifies the Stripe signature correctly but
    has no `processed_events` lookup — so a 5xx + redelivery would replay
    every Supabase upsert. The combo is the right place to surface that."""
    from supervisor_discover.combos import detect_combos
    findings = scan_all(VERCEL_SAAS_FIXTURE)
    combos = detect_combos(findings)
    ids = {c.id for c in combos}
    assert "webhook-plus-db-write" in ids
    hit = next(c for c in combos if c.id == "webhook-plus-db-write")
    assert hit.severity == "high"
    assert "idempotency" in hit.title.lower()


def test_vercel_saas_sql_rls_audit():
    """SQL DDL pass: a table without `enable row level security` is high-
    confidence (anon key has full access on Supabase). A table with RLS
    enabled but no policy is medium (locked out by default; confirm
    intent). Tables with both RLS and a policy emit nothing."""
    findings = scan_all(VERCEL_SAAS_FIXTURE)
    rls = [f for f in findings
           if (f.extra or {}).get("family", "").startswith("rls-")]
    by_table = {f.extra["table"]: f for f in rls}
    assert "users" not in by_table  # RLS + 2 policies → silent
    assert by_table["customers"].confidence == "medium"
    assert by_table["customers"].extra["family"] == "rls-no-policy"
    assert by_table["audit_events"].confidence == "high"
    assert by_table["audit_events"].extra["family"] == "rls-missing"


def test_sqlite_schema_does_not_emit_rls_findings(tmp_path):
    """SQLite DDL is not a Supabase/Postgres RLS surface.

    The scanner should still report runtime SQL mutations elsewhere; only the
    RLS DDL audit is gated by dialect evidence.
    """
    from supervisor_discover.scanners.db_mutations import scan as scan_db

    server = tmp_path / "server"
    server.mkdir()
    (server / "schema.sql").write_text(
        "PRAGMA foreign_keys=ON;\n"
        "\n"
        "CREATE TABLE IF NOT EXISTS reservations (\n"
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "  name TEXT NOT NULL\n"
        ");\n"
        "\n"
        "CREATE TABLE IF NOT EXISTS leads (\n"
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "  email TEXT NOT NULL\n"
        ");\n"
        "\n"
        "CREATE TABLE IF NOT EXISTS admin_users (\n"
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "  email TEXT UNIQUE NOT NULL\n"
        ");\n"
    )
    (server / "index.js").write_text(
        "db.prepare('INSERT INTO leads (email) VALUES (?)').run(email);\n"
    )

    findings = scan_db(tmp_path)
    rls = [
        f for f in findings
        if (f.extra or {}).get("family", "").startswith("rls-")
    ]
    inserts = [
        f for f in findings
        if f.scanner == "db-mutations" and (f.extra or {}).get("verb") == "INSERT"
    ]
    assert rls == []
    assert len(inserts) == 1
    assert inserts[0].extra["table"] == "leads"


def test_skip_dirs_check_is_relative_to_scan_root(tmp_path):
    """Regression: repos inside ~/Library/CloudStorage/Dropbox (or any path
    whose absolute parts contain a _SKIP_DIRS entry like 'Library') must
    still be scanned. The skip check applies to paths relative to the
    scan root, not the full absolute path."""
    # Build a repo whose PARENT directory name is in _SKIP_DIRS.
    # "Library" is in the skip list for $HOME/Library exclusion.
    fake_host = tmp_path / "Library" / "CloudStorage" / "Dropbox" / "my_repo"
    fake_host.mkdir(parents=True)
    py_file = fake_host / "main.py"
    py_file.write_text("# some trading code\nimport openai\n")

    # Scanning the repo root (inside Library/…) should find main.py.
    files = list(python_files(fake_host))
    assert py_file in files, (
        "_walk should scan files in a repo even when the absolute path "
        "contains a _SKIP_DIRS name above the scan root"
    )


def test_db_mutations_on_customer_table_go_to_customer_data(tmp_path):
    """`INSERT INTO users` → customer_data tier (PII)."""
    from supervisor_discover.classifier import tier_of
    from supervisor_discover.findings import Finding

    f = Finding(
        scanner="db-mutations", file="/r/app.py", line=1, snippet="INSERT INTO users",
        suggested_action_type="account_change", confidence="high", rationale="x",
        extra={"table": "users", "verb": "INSERT"},
    )
    assert tier_of(f) == "customer_data"


def test_nestjs_controller_without_llm_or_branching_skipped(tmp_path):
    """The 10-repo benchmark caught medusa (NestJS) and erpnext (Frappe)
    inflating priority because the regex matched any `*Controller`. A
    plain MVC controller — no LLM import, no decision-branching, just
    HTTP routes — must NOT emit an agent-class finding."""
    from supervisor_discover.scanners.agent_orchestrators import scan as scan_orch

    src = tmp_path / "src" / "users"
    src.mkdir(parents=True)
    (src / "users.controller.ts").write_text(
        "import { Controller, Get, Post } from '@nestjs/common';\n"
        "import { UsersService } from './users.service';\n"
        "\n"
        "@Controller('users')\n"
        "export class UsersController {\n"
        "  constructor(private readonly users: UsersService) {}\n"
        "\n"
        "  @Get() list() { return this.users.list(); }\n"
        "  @Post() create(@Body() dto) { return this.users.create(dto); }\n"
        "}\n"
    )
    findings = [
        f for f in scan_orch(tmp_path)
        if f.scanner == "agent-orchestrators"
        and (f.extra or {}).get("kind") == "agent-class"
    ]
    assert findings == [], (
        "NestJS *Controller* must not register as agent-class without LLM "
        "import or decision-branching. Got: "
        f"{[(f.file, f.line, f.snippet) for f in findings]}"
    )


def test_controller_with_llm_import_still_fires(tmp_path):
    """When a `*Controller` class lives in a file that imports an LLM SDK,
    the gate is satisfied — this *is* an agent path."""
    from supervisor_discover.scanners.agent_orchestrators import scan as scan_orch

    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "agent_controller.py").write_text(
        "import openai\n"
        "\n"
        "class LLMController:\n"
        "    def dispatch(self, intent):\n"
        "        if intent == 'summary':\n"
        "            return openai.chat.completions.create(model='gpt-4', messages=[])\n"
        "        return None\n"
    )
    findings = [
        f for f in scan_orch(tmp_path)
        if f.scanner == "agent-orchestrators"
        and (f.extra or {}).get("kind") == "agent-class"
        and (f.extra or {}).get("class_name") == "LLMController"
    ]
    assert len(findings) == 1


def test_controller_with_decision_branching_still_fires(tmp_path):
    """Decision-branching on `action` / `intent` inside the Controller is
    the second positive signal — covers agents that don't import an LLM
    SDK directly."""
    from supervisor_discover.scanners.agent_orchestrators import scan as scan_orch

    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "router_controller.py").write_text(
        "class RouterController:\n"
        "    def handle(self, action):\n"
        "        if action == 'create':\n"
        "            return self._create()\n"
        "        if action == 'delete':\n"
        "            return self._delete()\n"
        "        if action == 'update':\n"
        "            return self._update()\n"
        "        return None\n"
    )
    findings = [
        f for f in scan_orch(tmp_path)
        if (f.extra or {}).get("class_name") == "RouterController"
    ]
    assert len(findings) == 1


def test_dispatcher_match_unaffected_by_controller_gate(tmp_path):
    """`Dispatcher` is one of the non-Controller agent tokens — it fires
    unconditionally even without LLM imports or branching."""
    from supervisor_discover.scanners.agent_orchestrators import scan as scan_orch

    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "dispatcher.py").write_text(
        "class AlertDispatcher:\n"
        "    def dispatch(self):\n"
        "        return None\n"
    )
    findings = [
        f for f in scan_orch(tmp_path)
        if (f.extra or {}).get("class_name") == "AlertDispatcher"
    ]
    assert len(findings) == 1


def test_db_mutations_finds_raw_sql_in_sql_files(tmp_path):
    """`*.sql` files loaded via `aiosql.from_path(...)` are invisible to
    the Python scanner — fastapi-realworld was the canonical miss. The
    .sql walker must catch INSERT/UPDATE/DELETE in those files and tag
    the finding with `source_kind=sql-file` so the renderer can pivot
    its copy."""
    from supervisor_discover.scanners.db_mutations import scan as scan_db

    sql_dir = tmp_path / "app" / "db" / "queries" / "sql"
    sql_dir.mkdir(parents=True)
    (sql_dir / "users.sql").write_text(
        "-- name: create-user\n"
        "INSERT INTO users (username, email, salt, hashed_password)\n"
        "VALUES (:username, :email, :salt, :hashed_password)\n"
        "RETURNING id;\n"
        "\n"
        "-- name: update-user\n"
        "UPDATE users SET email = :email WHERE id = :id;\n"
    )
    findings = scan_db(tmp_path)
    by_verb = {f.extra["verb"]: f for f in findings if f.scanner == "db-mutations"}
    assert "INSERT" in by_verb
    assert "UPDATE" in by_verb
    assert by_verb["INSERT"].extra["table"] == "users"
    assert by_verb["INSERT"].suggested_action_type == "account_change"
    assert by_verb["INSERT"].extra["source_kind"] == "sql-file"


def test_db_mutations_sql_files_ignore_commented_verbs(tmp_path):
    """Trap fixture: `-- TODO: UPDATE the schema later` (a comment) and
    `/* DELETE FROM old_users */` must NOT fire. The verb is real text in
    the file; only the regex on stripped content should match."""
    from supervisor_discover.scanners.db_mutations import scan as scan_db

    sql_dir = tmp_path / "queries"
    sql_dir.mkdir(parents=True)
    (sql_dir / "trap.sql").write_text(
        "-- TODO: UPDATE the schema later, once we migrate.\n"
        "/* DELETE FROM old_users — held for review */\n"
        "SELECT 1;\n"
    )
    findings = [
        f for f in scan_db(tmp_path)
        if f.scanner == "db-mutations" and (f.extra or {}).get("source_kind") == "sql-file"
    ]
    assert findings == [], f"comments leaked into findings: {findings}"


def test_db_mutations_on_business_table_go_to_business_data(tmp_path):
    """`INSERT INTO trades` → business_data tier (NOT customer PII)."""
    from supervisor_discover.classifier import tier_of
    from supervisor_discover.findings import Finding

    for table in ("trades", "positions", "inventory", "events", "orders_history",
                  "products", "logs", "metrics"):
        f = Finding(
            scanner="db-mutations", file="/r/app.py", line=1,
            snippet=f"INSERT INTO {table}",
            suggested_action_type="other", confidence="medium", rationale="x",
            extra={"table": table, "verb": "INSERT"},
        )
        assert tier_of(f) == "business_data", f"table `{table}` should go to business_data"


def test_skip_dirs_still_filters_within_the_repo(tmp_path):
    """Complementary check: build/cache dirs INSIDE the scanned repo are
    still skipped (the common case we care about)."""
    repo = tmp_path / "my_repo"
    (repo / "src").mkdir(parents=True)
    (repo / "node_modules" / "lib").mkdir(parents=True)
    (repo / ".venv").mkdir()

    real = repo / "src" / "app.py"
    real.write_text("x = 1")
    noise_a = repo / "node_modules" / "lib" / "pkg.py"
    noise_a.write_text("y = 2")
    noise_b = repo / ".venv" / "site.py"
    noise_b.write_text("z = 3")

    files = list(python_files(repo))
    assert real in files
    assert noise_a not in files
    assert noise_b not in files
