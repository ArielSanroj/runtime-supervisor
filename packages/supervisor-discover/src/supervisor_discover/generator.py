"""Emit the runtime-supervisor/ output directory."""
from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .classifier import TIER_ORDER, Tier, group_by_action_type, group_by_risk_tier
from .combo_playbooks import render_index as render_combos_index, render_playbook
from .combos import detect_combos, render_markdown as render_combos_md
from .findings import Finding
from .narrator import render_summary as render_summary_email
from .rollout import render_rollout_md
from .summary import build_summary, render_markdown as render_summary_md
from .templates import (
    CI_WORKFLOW,
    ENV_EXAMPLE,
    PY_STUB,
    REPORT_HEADER,
    TIER_COPY,
    TS_STUB,
)

# Where the supervisor's own seed policies live — the generator copies them
# verbatim so the customer starts with the same baseline the supervisor
# ships with.
_POLICY_SOURCE_DIR = Path(__file__).resolve().parents[4] / "packages" / "policies"


def _safe_filename(path: str) -> str:
    rel = path.rsplit("/", 1)[-1]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", rel)


def generate(findings: list[Finding], out_dir: Path, repo_root: Path | None = None) -> None:
    """Emit the runtime-supervisor/ output directory.

    `repo_root`, when provided, becomes the basename in SUMMARY.md's title.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = build_summary(findings)
    repo_name = repo_root.name if repo_root else None

    # findings.json — wrapped now: top-level "findings" + "repo_summary".
    # CI consumers that diff findings[] keep working; new consumers can read
    # repo_summary for the briefing data.
    sorted_findings = sorted(
        [f.to_dict() for f in findings],
        key=lambda d: (d["file"], d["line"], d["scanner"]),
    )
    payload: dict[str, Any] = {
        "repo_summary": summary.to_dict(),
        "findings": sorted_findings,
    }
    (out_dir / "findings.json").write_text(json.dumps(payload, indent=2) + "\n")

    # report.md — summary first, then critical combos (if any), then guardrails, then tier-by-risk.
    by_type = Counter(f.suggested_action_type for f in findings)
    tier_summary_table, headline_note = _tier_summary(findings)
    combos = detect_combos(findings)
    report = render_summary_md(summary)
    if combos:
        report += "\n---\n\n"
        report += render_combos_md(combos)
    report += _render_applicable_guardrails(findings)
    report += "\n---\n\n"
    report += REPORT_HEADER.format(
        total=len(findings),
        tier_summary_table=tier_summary_table,
        headline_note=headline_note,
    )
    report += _render_by_risk_tier(findings)
    (out_dir / "report.md").write_text(report)

    # ROLLOUT.md — tailored to the repo's stack + surface + tier counts.
    (out_dir / "ROLLOUT.md").write_text(render_rollout_md(summary, findings))

    # SUMMARY.md — the mandable "security review email". report.md is the
    # technical doc; SUMMARY.md is the thing you paste in a PR or DM.
    (out_dir / "SUMMARY.md").write_text(
        render_summary_email(summary, findings, combos, repo_name=repo_name)
    )

    # policies — copy from supervisor's source dir for live action types
    policies_dir = out_dir / "policies"
    policies_dir.mkdir(exist_ok=True)
    for action_type in sorted(set(by_type.keys()) - {"other"}):
        src = _POLICY_SOURCE_DIR / f"{action_type}.base.v1.yaml"
        dst = policies_dir / f"{action_type}.base.v1.yaml"
        if src.exists():
            shutil.copyfile(src, dst)
        else:
            dst.write_text(_policy_template(action_type))

    # combos/ — Nivel 1 remediation playbooks per detected combo.
    # Writes one markdown per combo + an index README. Combo-specific
    # policies also land in policies/ (created above) so the user can
    # copy-paste them into the supervisor without extra ceremony.
    if combos:
        combos_dir = out_dir / "combos"
        combos_dir.mkdir(exist_ok=True)
        for combo in combos:
            pb = render_playbook(combo, findings, summary)
            (combos_dir / f"{combo.id}.md").write_text(pb.markdown)
            if pb.policy_yaml:
                (policies_dir / f"tool_use.{combo.id}.v1.yaml").write_text(pb.policy_yaml)
        (combos_dir / "README.md").write_text(render_combos_index(combos))

    # stubs (one per call-site of high-confidence payment/LLM findings)
    stubs_py = out_dir / "stubs" / "py"
    stubs_ts = out_dir / "stubs" / "ts"
    stubs_py.mkdir(parents=True, exist_ok=True)
    stubs_ts.mkdir(parents=True, exist_ok=True)
    for f in findings:
        if f.confidence == "low" or f.suggested_action_type == "other":
            continue
        stub_name = f"{_safe_filename(f.file)}_L{f.line}"
        if f.file.endswith(".py"):
            (stubs_py / f"{stub_name}.stub.py").write_text(
                PY_STUB.format(original_file=f.file, line=f.line, snippet=f.snippet,
                               action_type=f.suggested_action_type, rationale=f.rationale)
            )
        else:
            (stubs_ts / f"{stub_name}.stub.ts").write_text(
                TS_STUB.format(original_file=f.file, line=f.line, snippet=f.snippet,
                               action_type=f.suggested_action_type, rationale=f.rationale)
            )

    # .env.example
    (out_dir / ".env.example").write_text(ENV_EXAMPLE)

    # CI workflow
    ci_dir = out_dir / ".github" / "workflows"
    ci_dir.mkdir(parents=True, exist_ok=True)
    (ci_dir / "runtime-supervisor.yml").write_text(CI_WORKFLOW)


# OWASP LLM Top 10 coverage per action_type. The supervisor's threat
# pipeline runs these detectors on every evaluate() call regardless of
# action_type, but this table says which are MOST relevant — what the
# reader should care about for each kind of action.
_OWASP_PER_ACTION_TYPE: dict[str, list[tuple[str, str]]] = {
    "refund": [
        ("LLM01", "Prompt injection — el monto o el motivo pueden venir inyectados"),
        ("LLM02", "Sensitive info disclosure — customer_id y reason pueden filtrar PII"),
    ],
    "payment": [
        ("LLM01", "Prompt injection — monto/destino pueden venir inyectados"),
        ("LLM10", "Unbounded consumption — bursts de payments = fraude o DoS"),
    ],
    "account_change": [
        ("LLM01", "Prompt injection — el nuevo email/password puede venir del attacker"),
        ("LLM02", "Sensitive info disclosure — email/phone son PII"),
    ],
    "data_access": [
        ("LLM02", "Sensitive info disclosure — el objetivo del query es exfiltrar data"),
        ("LLM10", "Unbounded consumption — queries sin límite agotan DB"),
    ],
    "tool_use": [
        ("LLM01", "Prompt injection — el prompt es la superficie primaria"),
        ("LLM06", "Jailbreak — evadir guardrails del modelo"),
        ("LLM10", "Unbounded consumption — prompts gigantes/loops infinitos"),
    ],
    "compliance": [
        ("LLM09", "Overreliance — no delegar decisiones de compliance al agente solo"),
    ],
}


def _load_policy_rules(action_type: str) -> list[dict[str, Any]] | None:
    """Read the policy YAML for an action_type and return its rules list.
    Returns None when no policy is shipped — caller renders a placeholder."""
    src = _POLICY_SOURCE_DIR / f"{action_type}.base.v1.yaml"
    if not src.exists():
        return None
    try:
        data = yaml.safe_load(src.read_text())
        return data.get("rules") or []
    except (yaml.YAMLError, OSError):
        return None


def _render_applicable_guardrails(findings: list[Finding]) -> str:
    """For each action_type present in findings, describe which policy applies,
    what its rules do, and which OWASP threats the supervisor catches."""
    buckets = group_by_action_type(findings)
    if not buckets:
        return ""

    lines: list[str] = ["\n## Guardrails que el supervisor aplicaría", ""]
    lines.append(
        "Lo que pasa cuando un agente intenta ejecutar cada acción: "
        "el supervisor corre la política listada, más el pipeline OWASP LLM Top 10. "
        "Si la política o un detector de amenaza matchea, la acción se bloquea o va a review."
    )
    lines.append("")

    for action_type in sorted(buckets.keys()):
        items = buckets[action_type]
        if action_type == "other":
            continue

        rules = _load_policy_rules(action_type)
        owasp = _OWASP_PER_ACTION_TYPE.get(action_type, [])

        # Show the scanners that emitted this action_type so the reader
        # knows whether "tool_use" here means LLM calls, email/shell, or
        # agent-orchestrator — the policy name alone is ambiguous.
        scanners_used = sorted({f.scanner for f in items})
        scanners_str = f" — via {', '.join(scanners_used)}" if scanners_used else ""
        lines.append(f"### Policy `{action_type}.base.v1` — {len(items)} call-site(s){scanners_str}")
        lines.append("")

        # Policy rules block
        if rules is None:
            lines.append(
                f"**Política:** `{action_type}.base.v1` (no hay YAML todavía). "
                "El scanner generó un template placeholder en "
                f"`runtime-supervisor/policies/{action_type}.base.v1.yaml` — editalo "
                "con las reglas reales y promovelo vía `POST /v1/policies`."
            )
        else:
            lines.append(f"**Política:** `{action_type}.base.v1` ({len(rules)} reglas)")
            for rule in rules:
                rule_id = rule.get("id", "?")
                action = str(rule.get("action", "?")).upper()
                reason = rule.get("reason", "?")
                explanation = rule.get("explanation", "").strip()
                lines.append(f"  - **{action}** · `{rule_id}` — {reason}")
                if explanation:
                    # Collapse multiline YAML folded explanations into one paragraph.
                    collapsed = " ".join(explanation.split())
                    lines.append(f"    _{collapsed}_")
        lines.append("")

        # OWASP threats block
        if owasp:
            lines.append("**Amenazas OWASP LLM cubiertas por el threat pipeline:**")
            for ref, desc in owasp:
                lines.append(f"  - **{ref}** — {desc}")
            lines.append("")

        # Call-sites
        lines.append("**Call-sites detectados:**")
        for f in items[:10]:
            conf_badge = f" [{f.confidence}]" if f.confidence != "low" else ""
            lines.append(f"  {f.file.split('/')[-1]}:{f.line} — `{f.snippet}`{conf_badge}")
        if len(items) > 10:
            lines.append(f"  … y {len(items) - 10} más (ver tabla completa abajo).")
        lines.append("")

    return "\n".join(lines) + "\n"


def _tier_summary(findings: list[Finding]) -> tuple[str, str]:
    """Returns (markdown table, headline note). The table goes at the top of
    the report so the reader sees counts per tier before scrolling into
    details."""
    buckets = group_by_risk_tier(findings)
    rows: list[str] = []
    headline_high = 0
    for tier in TIER_ORDER:
        items = buckets[tier]
        high = sum(1 for f in items if f.confidence == "high")
        med = sum(1 for f in items if f.confidence == "medium")
        low = sum(1 for f in items if f.confidence == "low")
        total = len(items)
        title = TIER_COPY[tier]["title"]
        rows.append(f"| **{title}** | {high} | {med} | {low} | {total} |")
        if tier in ("money", "customer_data", "llm"):
            headline_high += high
    if headline_high == 0:
        note = (
            "_Ningún hallazgo de alta confianza en los tiers críticos. Esto normalmente "
            "significa (a) tu repo no usa los SDKs que los scanners conocen, (b) los "
            "imports son indirectos y necesitan rescan tras wrapping, o (c) realmente no "
            "hay superficie crítica sin supervisar. Revisa los tiers abajo para confirmar._"
        )
    else:
        note = (
            f"**{headline_high} call-site(s) de alta confianza esperan stub.** Revisa los "
            "tiers abajo en orden (los de arriba mueven dinero o tocan datos críticos)."
        )
    return "\n".join(rows), note


def _render_by_risk_tier(findings: list[Finding]) -> str:
    if not findings:
        return "_No findings — either nothing to supervise, or the scanners didn't recognize anything._\n"
    buckets = group_by_risk_tier(findings)
    lines: list[str] = []

    for tier in TIER_ORDER:
        items = buckets[tier]
        if not items:
            continue
        # The headline tiers (money, customer_data, llm) get the full
        # Observa/Evalúa/Intervendría block and an expanded findings table.
        # `general` is demoted to a collapsed footer at the end.
        if tier == "general":
            continue
        lines.extend(_render_tier_block(tier, items, collapse=False))

    # General / informational goes at the bottom, collapsed.
    general = buckets["general"]
    if general:
        lines.extend(_render_tier_block("general", general, collapse=True))

    return "\n".join(lines) + "\n"


def _top_files_evidence(items: list[Finding], limit: int = 3) -> str:
    """Render the top-N findings (by confidence desc) as backticked
    `short-path:line` references joined with ` · `. Used in tier blocks'
    '📍 En tu repo' line so the reader sees exactly which files matter."""
    order = {"high": 0, "medium": 1, "low": 2}
    sorted_items = sorted(items, key=lambda f: (order.get(f.confidence, 3), f.file))
    top = sorted_items[:limit]
    shorts = []
    for f in top:
        parts = f.file.rsplit("/", 2)
        short = "/".join(parts[-2:]) if len(parts) > 1 else f.file
        shorts.append(f"`{short}:{f.line}`")
    rendered = " · ".join(shorts)
    if len(items) > limit:
        rendered += f" _+{len(items) - limit} más_"
    return rendered


def _render_tier_block(tier: Tier, items: list[Finding], *, collapse: bool) -> list[str]:
    copy = TIER_COPY[tier]
    high = [f for f in items if f.confidence == "high"]
    medium = [f for f in items if f.confidence == "medium"]
    low = [f for f in items if f.confidence == "low"]

    lines: list[str] = []
    if collapse:
        lines.append(f"<details>\n<summary><strong>{copy['title']}</strong> ({len(items)} informational findings — click to expand)</summary>\n")
    else:
        headline = f"## {copy['title']} — {len(high)} high / {len(medium)} medium / {len(low)} low"
        lines.append(headline)
        lines.append("")
        # Tri-part block: 🔴 Problema · 📍 En tu repo · ✅ Solución · (footnote)
        lines.append(f"🔴 **Problema:** {copy['problem']}")
        lines.append("")
        top_files = _top_files_evidence(items, limit=3)
        in_repo_prefix = copy["in_your_repo_prefix"].format(total=len(items))
        lines.append(f"📍 **En tu repo:** {in_repo_prefix}")
        if top_files:
            lines.append(f"    Top call-sites: {top_files}.")
        lines.append("")
        lines.append(f"✅ **La solución:** {copy['solution']}")
        lines.append("")
        # Optional 💡 runtime behavior — what the supervisor does at call time.
        # This is the "old intervendría" detail, kept so the reader understands
        # block vs review vs shadow semantics, not just the wrap pattern.
        runtime = copy.get("runtime_behavior", "")
        if runtime:
            lines.append(f"💡 **En runtime:** {runtime}")
            lines.append("")
        footnote = copy.get("technical_footnote", "")
        if footnote:
            lines.append(footnote)
            lines.append("")

    if collapse:
        # General tier: one simple table inside the <details>, no duplication.
        lines.append("| Scanner | File:Line | Snippet |")
        lines.append("|---|---|---|")
        for f in items:
            lines.append(f"| `{f.scanner}` | `{f.file}`:{f.line} | `{f.snippet}` |")
        lines.append("")
        lines.append("</details>\n")
        return lines

    # Headline tiers: high+medium in a rich table, low in a nested <details>.
    if high or medium:
        lines.append("| Confianza | Scanner | File:Line | Snippet | Rationale |")
        lines.append("|---|---|---|---|---|")
        for f in high + medium:
            lines.append(
                f"| {f.confidence} | `{f.scanner}` | `{f.file}`:{f.line} | `{f.snippet}` | {f.rationale} |"
            )
        lines.append("")

    if low:
        lines.append(f"<details>\n<summary>{len(low)} low-confidence findings</summary>\n")
        lines.append("| Scanner | File:Line | Snippet | Rationale |")
        lines.append("|---|---|---|---|")
        for f in low:
            lines.append(f"| `{f.scanner}` | `{f.file}`:{f.line} | `{f.snippet}` | {f.rationale} |")
        lines.append("")
        lines.append("</details>\n")

    return lines


def _policy_template(action_type: str) -> str:
    return f"""# Starter policy for {action_type} — this action_type isn't one the
# supervisor ships with out of the box. Edit and promote via
# POST /v1/policies.
name: {action_type}.base
version: 1
rules:
  - id: hard-cap
    when: "False"  # TODO: replace with real expression
    action: deny
    reason: placeholder
"""
