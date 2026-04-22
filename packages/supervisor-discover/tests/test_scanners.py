from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all
from supervisor_discover.scanners._utils import python_files

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"
NEXT_FIXTURE = Path(__file__).parent / "fixtures/fake_next_app"


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
