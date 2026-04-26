"""Diff two `findings.json` payloads.

The point: today every scan is a snapshot. Without a diff, you can't tell
the team _"this PR introduced 3 new high-confidence wraps"_ — re-running
the scanner on every PR just produces another snapshot to read by hand.

This module gives the CLI two new behaviors:

  - `supervisor-discover diff --baseline X.json --current Y.json`
        Compare two scan outputs and print added / removed / changed
        findings, grouped by severity and by file. Returns 0 always
        (the command is informational).

  - `supervisor-discover scan ... --fail-on=new-high`
        Run a scan, diff against an existing baseline if one exists in
        the output dir, and exit non-zero when the budget is exceeded.
        Designed for CI gates: a PR that introduces a new high-confidence
        wrap target without justification fails the build.

Match logic uses the stable `id` field on each finding (12-char hash of
scanner + relative path + line + normalized snippet — see
`findings.stable_id`). Survives reformatting, comment edits on nearby
lines, and the repo being cloned to a different parent dir between
scans. ID changes only when the call's identifier or its constant args
genuinely change — which is exactly when we want it to look like a new
finding.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


Severity = Literal["high", "medium", "low"]
SEVERITIES: tuple[Severity, ...] = ("high", "medium", "low")


@dataclass(frozen=True)
class FindingRecord:
    """Just enough of a finding to drive the diff. Carries the original
    dict so the renderer can show useful context without re-parsing."""
    id: str
    scanner: str
    file: str
    line: int
    snippet: str
    confidence: Severity
    suppressed: bool
    raw: dict


@dataclass(frozen=True)
class DiffResult:
    """What changed between baseline and current."""
    added: list[FindingRecord]
    removed: list[FindingRecord]
    changed: list[tuple[FindingRecord, FindingRecord]]   # (baseline, current)

    def summary_counts(self) -> dict[str, dict[Severity, int]]:
        """Counts grouped by added/removed/changed × severity. Used by the
        renderer + the `--fail-on` budget check."""
        counts: dict[str, dict[Severity, int]] = {
            "added":   {"high": 0, "medium": 0, "low": 0},
            "removed": {"high": 0, "medium": 0, "low": 0},
            "changed": {"high": 0, "medium": 0, "low": 0},
        }
        for f in self.added:
            counts["added"][f.confidence] += 1
        for f in self.removed:
            counts["removed"][f.confidence] += 1
        for _, cur in self.changed:
            counts["changed"][cur.confidence] += 1
        return counts


def _records_from_payload(payload: dict, suppressed_visible: bool = True) -> dict[str, FindingRecord]:
    """Turn a `findings.json` payload into a dict keyed by stable id.

    `suppressed_visible=False` drops findings that were marked `suppressed`
    (`.supervisor-ignore`) — the diff would otherwise list them as removed
    when a new suppression rule lands. We default to True so the diff is
    honest: suppressed findings still exist on disk; only the human-facing
    priority list hides them.
    """
    out: dict[str, FindingRecord] = {}
    for raw in payload.get("findings", []):
        fid = raw.get("id") or ""
        if not fid:
            # Old schema (pre-1.0) — synthesize an id from file+line+scanner.
            # Diff quality drops without snippet hashing, but we don't crash.
            fid = f"{raw.get('scanner','?')}::{raw.get('file','?')}::{raw.get('line',0)}"
        suppressed = bool((raw.get("extra") or {}).get("suppressed"))
        if not suppressed_visible and suppressed:
            continue
        record = FindingRecord(
            id=fid,
            scanner=str(raw.get("scanner", "")),
            file=str(raw.get("file", "")),
            line=int(raw.get("line", 0) or 0),
            snippet=str(raw.get("snippet", "")),
            confidence=str(raw.get("confidence", "low")) if str(raw.get("confidence", "low")) in SEVERITIES else "low",
            suppressed=suppressed,
            raw=raw,
        )
        out[record.id] = record
    return out


def diff_payloads(baseline: dict, current: dict) -> DiffResult:
    """Compare two `findings.json` payloads (the dict you get from
    `json.load`). Returns added / removed / changed records.

    `changed` only fires when the same ID's confidence shifted (e.g.
    medium → high, or `already_gated` flipped). Same-ID + same-severity
    is treated as unchanged — the snippet text might differ slightly but
    the underlying call is the same.
    """
    base_records = _records_from_payload(baseline)
    cur_records = _records_from_payload(current)
    base_keys = set(base_records)
    cur_keys = set(cur_records)
    added = sorted(
        (cur_records[k] for k in cur_keys - base_keys),
        key=lambda r: (SEVERITIES.index(r.confidence), r.file, r.line),
    )
    removed = sorted(
        (base_records[k] for k in base_keys - cur_keys),
        key=lambda r: (SEVERITIES.index(r.confidence), r.file, r.line),
    )
    changed: list[tuple[FindingRecord, FindingRecord]] = []
    for k in base_keys & cur_keys:
        b, c = base_records[k], cur_records[k]
        if b.confidence != c.confidence or b.suppressed != c.suppressed:
            changed.append((b, c))
    changed.sort(key=lambda pair: (SEVERITIES.index(pair[1].confidence), pair[1].file, pair[1].line))
    return DiffResult(added=added, removed=removed, changed=changed)


def load_payload(path: Path) -> dict:
    """Read a `findings.json` (or compatible payload) from disk. Returns
    `{"findings": []}` when the file is missing or unreadable so first-time
    diff against an empty baseline still works."""
    if not path.is_file():
        return {"findings": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"findings": []}


# ─── Rendering ──────────────────────────────────────────────────────


def _short(file: str) -> str:
    parts = Path(file).parts
    if len(parts) <= 3:
        return file
    return ".../" + "/".join(parts[-2:])


def render_text(result: DiffResult) -> str:
    """Plain-text rendering for the CLI. Compact: one block per category,
    one line per finding. Empty result still renders the header so CI logs
    show 'no changes' explicitly."""
    counts = result.summary_counts()
    lines: list[str] = []
    lines.append("supervisor-discover diff:")
    lines.append("")
    lines.append(
        f"  +{counts['added']['high']} high  "
        f"+{counts['added']['medium']} medium  "
        f"+{counts['added']['low']} low      (added)"
    )
    lines.append(
        f"  -{counts['removed']['high']} high  "
        f"-{counts['removed']['medium']} medium  "
        f"-{counts['removed']['low']} low      (removed / resolved)"
    )
    if any(counts["changed"].values()):
        lines.append(
            f"   {counts['changed']['high']} high  "
            f"{counts['changed']['medium']} medium  "
            f"{counts['changed']['low']} low       (severity changed)"
        )
    lines.append("")
    if result.added:
        lines.append("Added:")
        for r in result.added[:20]:
            lines.append(f"  + [{r.confidence}] {_short(r.file)}:{r.line}  ({r.scanner}) {r.snippet[:50]}")
        if len(result.added) > 20:
            lines.append(f"  + … +{len(result.added) - 20} more")
        lines.append("")
    if result.removed:
        lines.append("Removed:")
        for r in result.removed[:20]:
            lines.append(f"  - [{r.confidence}] {_short(r.file)}:{r.line}  ({r.scanner})")
        if len(result.removed) > 20:
            lines.append(f"  - … +{len(result.removed) - 20} more")
        lines.append("")
    if result.changed:
        lines.append("Changed:")
        for b, c in result.changed[:20]:
            lines.append(
                f"  ~ {_short(c.file)}:{c.line}  "
                f"{b.confidence}→{c.confidence}  ({c.scanner})"
            )
        if len(result.changed) > 20:
            lines.append(f"  ~ … +{len(result.changed) - 20} more")
        lines.append("")
    if not (result.added or result.removed or result.changed):
        lines.append("  (no changes)")
        lines.append("")
    return "\n".join(lines)


# ─── CI gate ────────────────────────────────────────────────────────


_FAIL_ON_BUDGETS: dict[str, dict[Severity, int]] = {
    "any":        {"high": 0, "medium": 0, "low": 0},
    "new-low":    {"high": 0, "medium": 0, "low": 0},
    "new-medium": {"high": 0, "medium": 0, "low": -1},  # -1 = ignore
    "new-high":   {"high": 0, "medium": -1, "low": -1},
    "never":      {"high": -1, "medium": -1, "low": -1},
}


def exceeds_budget(result: DiffResult, fail_on: str) -> tuple[bool, str]:
    """Return (exceeded, reason). The reason is a human-readable line the
    CLI prints just before exit so the dev sees WHY their PR failed."""
    fail_on = fail_on.lower()
    if fail_on not in _FAIL_ON_BUDGETS:
        return False, f"unknown --fail-on value: {fail_on!r}"
    budget = _FAIL_ON_BUDGETS[fail_on]
    counts = result.summary_counts()
    for severity in SEVERITIES:
        threshold = budget[severity]
        if threshold < 0:
            continue
        added = counts["added"][severity]
        if added > threshold:
            reason = (
                f"--fail-on={fail_on}: {added} new {severity}-confidence "
                f"finding(s) introduced (budget: {threshold})."
            )
            return True, reason
    return False, ""
