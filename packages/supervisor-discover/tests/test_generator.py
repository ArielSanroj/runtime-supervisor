from __future__ import annotations

import json
from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.generator import generate
from supervisor_discover.scanners import scan_all

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"


def test_generator_writes_expected_tree(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "runtime-supervisor"
    generate(findings, out)

    assert (out / "report.md").exists()
    assert (out / "findings.json").exists()
    assert (out / ".env.example").exists()
    assert (out / ".github/workflows/runtime-supervisor.yml").exists()

    # Refund finding → real policy copied from supervisor source
    refund_policy = out / "policies/refund.base.v1.yaml"
    assert refund_policy.exists()
    assert "refund.base" in refund_policy.read_text()

    # Stubs emitted for the high-confidence findings (refund + openai)
    stub_files = list((out / "stubs/py").glob("*.stub.py"))
    assert stub_files, "expected at least one Python stub"
    any_refund = any("refund" in s.read_text() for s in stub_files)
    assert any_refund


def test_findings_json_is_sorted_for_stable_diff(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    payload = json.loads((out / "findings.json").read_text())
    keys = [(d["file"], d["line"], d["scanner"]) for d in payload]
    assert keys == sorted(keys)


def test_report_lists_next_steps(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    report = (out / "report.md").read_text()
    assert "Next steps" in report
    assert "supervisor-guards" in report
    assert "/v1/integrations" in report
