"""Emit the runtime-supervisor/ output directory."""
from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from pathlib import Path

from .classifier import group_by_action_type
from .findings import Finding
from .templates import CI_WORKFLOW, ENV_EXAMPLE, PY_STUB, REPORT_HEADER, TS_STUB

# Where the supervisor's own seed policies live — the generator copies them
# verbatim so the customer starts with the same baseline the supervisor
# ships with.
_POLICY_SOURCE_DIR = Path(__file__).resolve().parents[4] / "packages" / "policies"


def _safe_filename(path: str) -> str:
    rel = path.rsplit("/", 1)[-1]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", rel)


def generate(findings: list[Finding], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # findings.json — machine-readable, sorted for stable diffs
    payload = sorted([f.to_dict() for f in findings], key=lambda d: (d["file"], d["line"], d["scanner"]))
    (out_dir / "findings.json").write_text(json.dumps(payload, indent=2) + "\n")

    # report.md
    by_type = Counter(f.suggested_action_type for f in findings)
    by_conf = Counter(f.confidence for f in findings)
    report = REPORT_HEADER.format(
        total=len(findings),
        by_type=", ".join(f"{k}={v}" for k, v in sorted(by_type.items())) or "(none)",
        by_conf=", ".join(f"{k}={v}" for k, v in sorted(by_conf.items())) or "(none)",
    )
    report += _render_findings_table(findings)
    (out_dir / "report.md").write_text(report)

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


def _render_findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "_No findings — either nothing to supervise, or the scanners didn't recognize anything._\n"
    buckets = group_by_action_type(findings)
    lines: list[str] = []
    for action_type in sorted(buckets.keys()):
        lines.append(f"## {action_type}\n")
        lines.append("| Scanner | File:Line | Snippet | Confidence | Rationale |")
        lines.append("|---|---|---|---|---|")
        for f in buckets[action_type]:
            lines.append(
                f"| `{f.scanner}` | `{f.file}`:{f.line} | `{f.snippet}` | {f.confidence} | {f.rationale} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


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
