from __future__ import annotations

import json
from pathlib import Path

from supervisor_discover.classifier import validate
from supervisor_discover.findings import Finding
from supervisor_discover.generator import generate
from supervisor_discover.scanners import scan_all

FLASK_FIXTURE = Path(__file__).parent / "fixtures/fake_flask_app"
NEXT_FIXTURE = Path(__file__).parent / "fixtures/fake_next_app"


def test_generator_writes_expected_tree(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "runtime-supervisor"
    generate(findings, out)

    assert (out / "FULL_REPORT.md").exists()
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
    assert set(payload.keys()) == {"repo_summary", "findings"}
    keys = [(d["file"], d["line"], d["scanner"]) for d in payload["findings"]]
    assert keys == sorted(keys)


def test_report_is_tiered_with_rollout_guidance(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    report = (out / "FULL_REPORT.md").read_text()
    # Tier-by-risk structure + deploy-without-breaking-prod messaging.
    assert "Money movement" in report
    assert "LLM tool-use" in report
    assert "ROLLOUT.md" in report
    assert "/v1/metrics/enforcement" in report
    # Tier summary table at the top.
    assert "| Tier | High | Medium | Low | Total |" in report
    # Tri-part framing: 🔴 Problem / 📍 In your repo / ✅ Fix.
    assert "🔴 **Problem:**" in report
    assert "📍 **In your repo:**" in report
    assert "✅ **Fix:**" in report
    # 💡 Runtime behavior: block/review/shadow semantics — preserves the detail
    # about what the supervisor actually does at call time, not just the wrap
    # pattern.
    assert "💡 **Runtime behavior:**" in report
    # Operational note about env-var switching without redeploy survives
    # in ROLLOUT.md's shadow phase.
    rollout = (tmp_path / "rs" / "ROLLOUT.md").read_text()
    assert "SUPERVISOR_ENFORCEMENT_MODE" in rollout
    assert "no code redeploy" in rollout


def test_rollout_md_is_stack_aware_for_python_repo(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    rollout = (out / "ROLLOUT.md").read_text()

    # Phase structure is present + env-var is the primary control lever.
    assert "Shadow" in rollout
    assert "Enforce" in rollout
    assert "SUPERVISOR_ENFORCEMENT_MODE" in rollout
    # Rollback section with the no-redeploy escape hatch.
    assert "Rollback" in rollout
    # Python example for a Python repo — not TS.
    assert "supervisor_guards" in rollout
    assert "@runtime-supervisor/guards" not in rollout
    # Bootstrap snippet uses bare configure() — no hardcoded mode override
    # that would defeat the env-var-as-lever advice.
    assert 'enforcement_mode="shadow"' not in rollout
    assert 'enforcementMode:' not in rollout
    # Orphaned "tier 1/2/3" vocabulary is gone — tiers use real names.
    assert "tier 1" not in rollout.lower()
    assert "tier 2" not in rollout.lower()
    # Phases are criteria-gated, not calendar-gated.
    assert "week 1" not in rollout.lower()
    assert "week 2-3" not in rollout.lower()
    assert "exit criteria" in rollout.lower()


def test_rollout_md_is_stack_aware_for_typescript_repo(tmp_path):
    findings = validate(scan_all(NEXT_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    rollout = (out / "ROLLOUT.md").read_text()

    # TS repo → TS example in the config snippet.
    assert "@runtime-supervisor/guards" in rollout
    assert "import supervisor_guards as sg" not in rollout
    # Bare configure() — no explicit mode override in the bootstrap.
    assert "configure();" in rollout
    assert 'enforcementMode:' not in rollout
    # Env-var control is still the primary lever regardless of stack.
    assert "SUPERVISOR_ENFORCEMENT_MODE" in rollout


def test_rollout_md_adapts_to_empty_findings(tmp_path):
    out = tmp_path / "rs"
    generate([], out)
    rollout = (out / "ROLLOUT.md").read_text()
    # No call-sites → no multi-phase playbook, just a re-scan prompt.
    assert "Phase 1" not in rollout
    assert "re-scan" in rollout.lower() or "rescan" in rollout.lower()


def test_rollout_md_progression_orders_by_max_confidence(tmp_path):
    # Customer data has only medium findings; LLM has one high. The enforce
    # progression should target the sharpest risk first (LLM) even though
    # customer_data sits earlier in TIER_ORDER.
    findings = validate([
        Finding(
            scanner="db-mutations",
            file="/tmp/fake/app.py",
            line=10,
            snippet="UPDATE users SET email=...",
            suggested_action_type="account_change",
            confidence="medium",
            rationale="Medium-confidence mutation",
            extra={"table": "users", "verb": "UPDATE"},
        ),
        Finding(
            scanner="llm-calls",
            file="/tmp/fake/agent.py",
            line=22,
            snippet="anthropic.messages.create(...)",
            suggested_action_type="tool_use",
            confidence="high",
            rationale="High-confidence LLM tool-use",
            extra={"sdk": "anthropic"},
        ),
    ])
    out = tmp_path / "rs"
    generate(findings, out)
    rollout = (out / "ROLLOUT.md").read_text()

    # Progression line: "LLM tool-use → Customer data" (LLM first due to high).
    assert "**LLM tool-use → Customer data**" in rollout


def test_generated_output_has_no_rioplatense_voseo(tmp_path):
    # Neutral Latin American Spanish, no voseo. These are the specific forms
    # the user called out — enforce on ALL generated markdown (SUMMARY,
    # report, ROLLOUT, combos).
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)

    voseo_patterns = [
        # Imperatives (-ar / -er / -ir → vos forms)
        "pegá", "arrancá", "reiniciá", "cambiá", "ajustá", "seteá",
        "mirá", "dejá", "seguí", "corré", "mandá", "Preferí", "Revisá",
        "Re-escaneá", "regenerá", "excluí", "envolvelo", "promové",
        "verificá", "abrilo", "elegí", "abrí ", "Abrí ", "Editá", "editá",
        "Copiá", "copiá", "Pasá", "pasá", "probá", "Probá", "Escribí",
        "escribí", "Definí", "definí", "empezá", "grepeá", "Grepeá",
        "instalá", "Instalá", "copiá", "revisá",
        # Present indicative vos forms
        "querés", "tenés", "podés", "hacés", "sabés", "conocés",
        "entendés", "buscás", "pasás", "necesitás", "agregás", "medís",
        "avanzás", "corrés", "escribís", "probás",
        # Expressions
        "por vos",
    ]
    for doc in ("START_HERE.md", "ROLLOUT.md", "FULL_REPORT.md"):
        content = (out / doc).read_text()
        for p in voseo_patterns:
            assert p not in content, (
                f"{doc} contiene voseo rioplatense '{p}'. "
                f"Usar equivalente neutro (imperativo con tú)."
            )
    # Also check combo playbooks if any were generated
    combos_dir = out / "combos"
    if combos_dir.exists():
        for combo_file in combos_dir.glob("*.md"):
            content = combo_file.read_text()
            for p in voseo_patterns:
                assert p not in content, (
                    f"combos/{combo_file.name} contiene voseo '{p}'."
                )


def test_rollout_exit_criteria_include_repo_context(tmp_path):
    """Each exit-criterion 'why' must mention the real tier count
    (not the generic hardcoded floor)."""
    # Fixture con 5 findings de real_world_actions
    findings_small = validate([
        Finding(
            scanner="email-sends", file=f"/repo/mail_{i}.py", line=i * 10,
            snippet="smtplib.SMTP(", suggested_action_type="tool_use",
            confidence="high", rationale="test",
            extra={"family": "smtplib", "provider": "smtplib"},
        )
        for i in range(1, 6)
    ])
    out = tmp_path / "small"
    generate(findings_small, out)
    rollout_small = (out / "ROLLOUT.md").read_text()

    # Must mention "5 call-sites" in some "Why" rationale
    assert "5 call-sites" in rollout_small, (
        "small-repo rationale should cite its real count (5), not the generic 20"
    )

    # Fixture con 50 findings
    findings_big = validate([
        Finding(
            scanner="email-sends", file=f"/repo/mail_{i}.py", line=i,
            snippet="smtplib.SMTP(", suggested_action_type="tool_use",
            confidence="high", rationale="test",
            extra={"family": "smtplib", "provider": "smtplib"},
        )
        for i in range(1, 51)
    ])
    out2 = tmp_path / "big"
    generate(findings_big, out2)
    rollout_big = (out2 / "ROLLOUT.md").read_text()

    assert "50 call-sites" in rollout_big, (
        "large-repo rationale should cite its real count (50)"
    )


def test_rollout_por_que_is_not_identical_between_repos(tmp_path):
    """Two distinct fixtures → the generated _Why:_ lines are not byte-
    identical. If they were, the rationale would still be hardcoded."""
    findings_a = validate([
        Finding(
            scanner="email-sends", file="/repo_a/mailer.py", line=42,
            snippet="smtplib.SMTP(", suggested_action_type="tool_use",
            confidence="high", rationale="test",
            extra={"family": "smtplib", "provider": "smtplib"},
        ),
    ])
    findings_b = validate([
        Finding(
            scanner="voice-actions", file="/repo_b/phone.ts", line=99,
            snippet="twilio.calls.create", suggested_action_type="tool_use",
            confidence="high", rationale="test",
            extra={"provider": "twilio"},
        ),
    ])
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    generate(findings_a, out_a)
    generate(findings_b, out_b)

    por_que_a = [l for l in (out_a / "ROLLOUT.md").read_text().splitlines() if "_Why:" in l]
    por_que_b = [l for l in (out_b / "ROLLOUT.md").read_text().splitlines() if "_Why:" in l]

    # Both surfaces are real — both must produce "Why" lines.
    assert por_que_a and por_que_b

    # The rationale sets must differ (identical → copy is still hardcoded).
    assert set(por_que_a) != set(por_que_b), (
        "two repos with different findings produced identical '_Why:_' lines — "
        "the rationale is still hardcoded"
    )

    # Spot-check: el rationale de A menciona smtplib o mailer; el de B menciona twilio o phone.
    body_a = "\n".join(por_que_a).lower()
    body_b = "\n".join(por_que_b).lower()
    assert "mailer" in body_a or "smtplib" in body_a
    assert "phone" in body_b or "twilio" in body_b


def test_rollout_md_surface_block_only_lists_active_tiers(tmp_path):
    # Construct findings that touch only customer_data (no money, no LLM).
    findings = validate([
        Finding(
            scanner="db-mutations",
            file="/tmp/fake/app.py",
            line=10,
            snippet="UPDATE users SET email=...",
            suggested_action_type="account_change",
            confidence="high",
            rationale="Direct user mutation",
            extra={"table": "users", "verb": "UPDATE"},
        )
    ])
    out = tmp_path / "rs"
    generate(findings, out)
    rollout = (out / "ROLLOUT.md").read_text()

    # Customer data surface → mentioned. No money or LLM high → those
    # tiers should not appear in the surface list.
    assert "Customer data" in rollout
    assert "Money movement" not in rollout
    assert "LLM tool-use" not in rollout


def test_report_includes_applicable_guardrails_section(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    report = (out / "FULL_REPORT.md").read_text()
    assert "## Guardrails que el supervisor aplicaría" in report
    # Refund is present in the flask fixture → should show its policy + OWASP refs.
    assert "refund.base.v1" in report
    assert "Policy `refund.base.v1`" in report
    # OWASP refs are shown for known action_types.
    assert "LLM01" in report or "LLM02" in report


def test_findings_json_wraps_repo_summary(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    import json
    data = json.loads((out / "findings.json").read_text())
    assert set(data.keys()) == {"repo_summary", "findings"}
    assert "frameworks" in data["repo_summary"]
    assert "total_findings" in data["repo_summary"]


def test_stubs_default_to_shadow_onreview(tmp_path):
    findings = validate(scan_all(FLASK_FIXTURE))
    out = tmp_path / "rs"
    generate(findings, out)
    stub_files = list((out / "stubs/py").glob("*.stub.py"))
    assert stub_files, "expected at least one Python stub"
    for s in stub_files:
        text = s.read_text()
        assert 'on_review="shadow"' in text, f"{s.name} must default to on_review='shadow'"
