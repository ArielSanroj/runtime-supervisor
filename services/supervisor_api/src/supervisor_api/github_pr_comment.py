"""Build the markdown body that gets posted on a PR.

Single-purpose module so the formatter can be unit-tested without
involving the dispatcher / HTTP client. Output mirrors what the
dashboard's diff drill-down shows at /repos/{repo_id}/history/{scan_id}
so users see the same shape in two places.
"""
from __future__ import annotations

from dataclasses import dataclass

from supervisor_discover.findings import Confidence, Finding


@dataclass(frozen=True)
class PrCommentInputs:
    repo_full_name: str
    repo_id: str
    pr_number: int
    head_sha: str
    new_findings: list[Finding]
    fixed_count: int
    site_url: str


def render_pr_comment(inputs: PrCommentInputs) -> str:
    """Returns the markdown body. Empty new + zero fixed = empty string;
    caller should skip posting in that case so we don't spam clean PRs.
    """
    if not inputs.new_findings and inputs.fixed_count == 0:
        return ""

    parts: list[str] = []

    if inputs.new_findings:
        n = len(inputs.new_findings)
        parts.append(
            f"🔒 **vibefixing detected {n} new unsafe call-site"
            f"{'s' if n != 1 else ''}** in this PR"
        )
        parts.append("")
        parts.append("| File | Type | Confidence | Why |")
        parts.append("|---|---|---|---|")
        for f in _sort_for_pr(inputs.new_findings)[:25]:
            parts.append(_row(f))
        if len(inputs.new_findings) > 25:
            parts.append(
                f"| _… and {len(inputs.new_findings) - 25} more — see full diff_ | | | |"
            )
        parts.append("")
        parts.append(
            "Wrap them with the matching `@supervised(...)` family before merging, "
            "or this lands in production ungated."
        )
    else:
        parts.append("✅ **No new unsafe call-sites in this PR.**")
        parts.append("")

    if inputs.fixed_count > 0:
        parts.append("")
        parts.append(
            f"Plus {inputs.fixed_count} previously-flagged finding"
            f"{'s' if inputs.fixed_count != 1 else ''} that {'are' if inputs.fixed_count != 1 else 'is'} no longer present — nice."
        )

    parts.append("")
    parts.append("---")
    parts.append(
        f"📊 [Full diff and policy suggestions →]"
        f"({inputs.site_url.rstrip('/')}/repos/{inputs.repo_id}) "
        f"· `head` `{inputs.head_sha[:7]}` · scanned by [vibefixing]"
        f"({inputs.site_url.rstrip('/')})"
    )

    return "\n".join(parts)


def _row(f: Finding) -> str:
    extra = f.extra or {}
    family = extra.get("family") or extra.get("kind") or ""
    why = (
        f.rationale.replace("\n", " ").replace("|", "\\|")[:120]
        if f.rationale
        else f.scanner
    )
    family_label = f" `{family}`" if family else ""
    return (
        f"| `{f.file}:{f.line}` | "
        f"`{f.suggested_action_type}`{family_label} | "
        f"{_confidence_emoji(f.confidence)} {f.confidence} | "
        f"{why} |"
    )


def _confidence_emoji(c: Confidence) -> str:
    return {"high": "🔴", "medium": "🟡", "low": "⚪"}.get(c, "⚪")


def _sort_for_pr(findings: list[Finding]) -> list[Finding]:
    """High-confidence first, then by tier (money/real-world above
    informational), then by file:line. Mirrors what /scan UI shows."""
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    tier_rank = {
        "payment": 0,
        "tool_use": 1,
        "account_change": 2,
        "data_access": 3,
        "compliance": 4,
        "general": 9,
    }
    return sorted(
        findings,
        key=lambda f: (
            confidence_rank.get(f.confidence, 9),
            tier_rank.get(f.suggested_action_type, 9),
            f.file,
            f.line,
        ),
    )
