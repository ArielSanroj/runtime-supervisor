from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners._utils import python_files

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"
NEXT_FIXTURE = Path(__file__).parent / "fixtures/fake_next_app"
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
    called in the same file. The wrapping module is the call-site to gate."""
    (tmp_path / "client.ts").write_text(
        'import OpenAI from "openai";\n'
        "const c = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n"
        "export default c;\n"
    )
    findings = scan_all(tmp_path)
    llm = [f for f in findings if f.scanner == "llm-calls"]
    assert llm, "expected llm-calls to fire on `new OpenAI()`"
    assert any(f.extra.get("kind") == "construction" for f in llm)


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
