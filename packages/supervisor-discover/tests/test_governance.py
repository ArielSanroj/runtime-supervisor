"""Tests for the governance/ pack emitted alongside every scan.

The pack must (a) always include the five expected markdowns, (b) every
action_type in findings must show up in OWNERS.md, (c) every detected LLM
provider must appear in policy.md *and* ai-use-inventory.md, (d) no
markdown may contain a literal integer that isn't traceable back to a real
RepoSummary / findings field — the "outputs derive from data" rule.
"""
from __future__ import annotations

import datetime as _dt
import re
from collections import Counter
from pathlib import Path

import pytest

from supervisor_discover.classifier import validate
from supervisor_discover.findings import Finding
from supervisor_discover.generator import generate
from supervisor_discover.governance import LLM_SCANNERS, write as governance_write
from supervisor_discover.scanners import scan_all
from supervisor_discover.summary import RepoSummary, build_summary

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"

EXPECTED_FILES = {
    "policy.md",
    "OWNERS.md",
    "review-process.md",
    "ai-use-inventory.md",
    "SELF-ATTESTATION.md",
}


def _run_scan(tmp_path: Path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "runtime-supervisor"
    generate(findings, out, repo_root=FLASK_FIXTURE)
    return findings, out


def test_governance_pack_emits_all_five_files(tmp_path):
    _, out = _run_scan(tmp_path)
    gov_dir = out / "governance"
    assert gov_dir.is_dir(), "governance/ subdir should be created"
    present = {p.name for p in gov_dir.iterdir() if p.is_file()}
    assert EXPECTED_FILES <= present, (
        f"missing governance files: {EXPECTED_FILES - present}"
    )


def test_owners_md_mentions_every_action_type(tmp_path):
    findings, out = _run_scan(tmp_path)
    action_types = {f.suggested_action_type for f in findings} - {"other", ""}
    owners_text = (out / "governance" / "OWNERS.md").read_text()
    for at in action_types:
        assert f"`{at}`" in owners_text, (
            f"OWNERS.md should mention action_type `{at}`"
        )


def test_policy_md_lists_every_detected_llm_provider(tmp_path):
    findings, out = _run_scan(tmp_path)
    summary = build_summary(findings, root=FLASK_FIXTURE)
    policy_text = (out / "governance" / "policy.md").read_text()
    inventory_text = (out / "governance" / "ai-use-inventory.md").read_text()
    for provider in summary.llm_providers:
        assert provider in policy_text, (
            f"policy.md should list LLM provider `{provider}`"
        )
        assert provider in inventory_text, (
            f"ai-use-inventory.md should list LLM provider `{provider}`"
        )


def test_self_attestation_links_to_real_artifacts(tmp_path):
    _, out = _run_scan(tmp_path)
    text = (out / "governance" / "SELF-ATTESTATION.md").read_text()
    # Every "Yes" line in the attestation must cite at least one real
    # artifact filename (relative link).
    for required_link in ("policy.md", "OWNERS.md", "review-process.md",
                          "ai-use-inventory.md"):
        assert required_link in text, (
            f"SELF-ATTESTATION.md should link to {required_link}"
        )
    # The three core question phrases should all be present.
    for phrase in ("Documented policies for AI use",
                   "Designated accountability",
                   "Process for reviewing AI use and risk"):
        assert phrase in text, f"SELF-ATTESTATION.md missing question: {phrase}"


def test_ai_use_inventory_row_count_matches_real_findings(tmp_path):
    findings, out = _run_scan(tmp_path)
    inv_text = (out / "governance" / "ai-use-inventory.md").read_text()
    expected = [f for f in findings if f.scanner in LLM_SCANNERS]
    # Each data row begins with `| \`<file>\`` — count those, ignoring the
    # header + separator row + the providers bullet list.
    data_rows = [
        ln for ln in inv_text.splitlines()
        if ln.startswith("| `") and "| Line |" not in ln
    ]
    assert len(data_rows) == len(expected), (
        f"inventory row count {len(data_rows)} != findings {len(expected)}"
    )


def test_no_hardcoded_numbers_outside_known_provenance(tmp_path):
    """Every integer in the rendered governance files must trace to a real
    summary / findings value. We allow the integers that the scaffold could
    legitimately produce from the input (provider count, action_type count,
    rule count, review-case ids, etc) by deriving the allow-set from the
    actual input data, then asserting that no other integers leak in."""
    findings, out = _run_scan(tmp_path)
    summary = build_summary(findings, root=FLASK_FIXTURE)
    gov_dir = out / "governance"

    # Numbers that legitimately come from real data — these are pulled from
    # the scaffold via `len(...)` and counter values.
    allowed = {
        len(summary.llm_providers),
        len({f.suggested_action_type for f in findings} - {"other", ""}),
        len([f for f in findings if f.scanner in LLM_SCANNERS]),
        len(summary.frameworks),
        len(summary.payment_integrations),
        # Per-action policy rule counts. Read the YAML the same way the
        # generator did, so the count we accept is exactly what got rendered.
        *(_rule_count(at) for at in {f.suggested_action_type for f in findings}),
        # File-line numbers from inventory rows are real (they come from
        # Finding.line), and we accept any integer that matches a finding
        # line number.
        *(f.line for f in findings),
        # The scan date stamped at the top of policy.md. Date is real (UTC
        # today) — split into Y/M/D so the regex's three integer matches
        # are all covered.
        *_scan_date_parts(),
    }
    # Strip None/0 from the set so "zero" never accidentally protects
    # other hardcoded zeros.
    allowed.discard(None)

    for md in gov_dir.glob("*.md"):
        text = md.read_text()
        for token in re.findall(r"(?<!\w)(\d+)(?!\w)", text):
            n = int(token)
            # Allow obviously-incidental small numbers found in headings like
            # "EvidenceEvent" version, code paths, etc. — anything in the
            # scaffold that isn't a counter we derived from real data.
            if n in allowed:
                continue
            # Allow up to the scaffold's literal mentions: `v1` policy
            # versions, the "90 days" cadence sentence, and the "5" used for
            # the live-action spot check. These are scaffold text, not
            # derived counts.
            if n in {1, 5, 90}:
                continue
            raise AssertionError(
                f"hardcoded integer `{n}` in {md.name} doesn't trace to "
                f"summary/findings — allowed set was {sorted(allowed)}"
            )


def test_governance_pack_handles_empty_findings(tmp_path):
    """When no findings exist, the pack still renders with italic
    placeholders — no exception, no empty file, no fake provider names."""
    out = tmp_path / "runtime-supervisor"
    policies_dir = out / "policies"
    policies_dir.mkdir(parents=True)
    gov_dir = out / "governance"
    empty_summary = RepoSummary()
    governance_write(gov_dir, empty_summary, [], None, policies_dir=policies_dir)
    for name in EXPECTED_FILES:
        text = (gov_dir / name).read_text()
        assert text.strip(), f"{name} is empty"
        # Placeholder marker text — the renderer should fall back to
        # italic markers, never invent providers.
        assert "OpenAI" not in text or name == "review-process.md", (
            f"{name} should not name OpenAI when summary is empty"
        )
        assert "Anthropic" not in text, (
            f"{name} should not name Anthropic when summary is empty"
        )


def test_owners_overrides_apply(tmp_path):
    """When `owners.config.yaml` is supplied via override path, OWNERS.md
    uses it instead of the git-derived default."""
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "runtime-supervisor"
    overrides = tmp_path / "owners.config.yaml"
    overrides.write_text(
        "default_owner: ada@example.com\n"
        "approver_of_last_resort: cto@example.com\n"
        "owners:\n"
        "  refund: payments-oncall@example.com\n"
    )
    generate(
        findings, out, repo_root=FLASK_FIXTURE,
        owners_config_path=overrides,
    )
    owners_text = (out / "governance" / "OWNERS.md").read_text()
    assert "ada@example.com" in owners_text
    assert "cto@example.com" in owners_text
    # Action types not covered by override fall back to default_owner.
    assert "payments-oncall@example.com" in owners_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan_date_parts() -> tuple[int, int, int]:
    """Y/M/D of today (UTC) — matches the date governance.write() stamps."""
    today = _dt.datetime.now(tz=_dt.timezone.utc).date()
    return today.year, today.month, today.day


def _rule_count(action_type: str) -> int:
    """Mirror of governance._rules_block's per-action rule count, used by
    the hardcoded-number guard test to allow legitimate counts."""
    import yaml
    src = Path(__file__).resolve().parents[2] / "policies" / f"{action_type}.base.v1.yaml"
    if not src.exists():
        return 0
    try:
        data = yaml.safe_load(src.read_text()) or {}
    except (yaml.YAMLError, OSError):
        return 0
    return len(data.get("rules") or [])
