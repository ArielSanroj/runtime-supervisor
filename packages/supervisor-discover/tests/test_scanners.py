from __future__ import annotations

from pathlib import Path

from supervisor_discover.scanners import scan_all

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
