"""Governance Pack — copy-paste artifacts for vendor questionnaires.

Generated as part of every scan. Sits next to `policies/`, `stubs/`, `combos/`
in the `runtime-supervisor/` output tree, in a sibling folder `governance/`.

Five markdown files, all derived from the real `RepoSummary` + `findings`
emitted by the scanner — no hardcoded numbers, no invented providers. When a
list is empty, the artifact renders an italic placeholder, never a literal
example.

The folder name is `governance/` (allowed in folder names per VOICE.md), but
every `.md` headline uses plain language ("AI Usage Policy", "Owners — who
approves what") rather than the compliance vocabulary VOICE.md keeps out of
titles.
"""
from __future__ import annotations

import datetime as _dt
import json
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

from .findings import Finding
from .summary import RepoSummary
from .templates import (
    ATTESTATION_SCAFFOLD,
    INVENTORY_SCAFFOLD,
    OWNERS_SCAFFOLD,
    POLICY_SCAFFOLD,
    REVIEW_PROCESS_SCAFFOLD,
)

# Scanners whose findings represent an AI / LLM / agent call-site for the
# inventory artifact. Kept here (not in policy_loader) because adding a new
# LLM scanner is a code change that should also update this set.
LLM_SCANNERS: frozenset[str] = frozenset({
    "llm-calls",
    "llm-output",
    "mcp-tools",
    "agent-orchestrators",
})


def write(
    out_dir: Path,
    summary: RepoSummary,
    findings: Sequence[Finding],
    repo_root: Path | None = None,
    *,
    policies_dir: Path,
    live_api_url: str | None = None,
    owners_config_path: Path | None = None,
) -> None:
    """Emit `out_dir/{policy,OWNERS,review-process,ai-use-inventory,SELF-ATTESTATION}.md`.

    All five files are deterministic given the same `summary` + `findings` +
    `owners.config.yaml`. When `live_api_url` is set, the attestation includes
    counts fetched from the supervisor API; on any failure the artifact falls
    back silently to the offline text.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    overrides = _load_owners_overrides(repo_root, owners_config_path)
    default_owner = overrides.get("default_owner") or _git_user_email(repo_root)
    approver = overrides.get("approver_of_last_resort") or default_owner
    action_owners: dict[str, str] = overrides.get("owners") or {}

    action_types = _action_types(findings)
    review_action_types = _review_action_types(action_types, policies_dir)
    inventory_rows = _inventory_rows(findings, repo_root)

    scan_iso_date = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%d")
    repo_name = repo_root.name if repo_root is not None else "this repo"

    (out_dir / "policy.md").write_text(_render_policy(
        repo_name=repo_name,
        scan_iso_date=scan_iso_date,
        summary=summary,
        action_types=action_types,
        policies_dir=policies_dir,
    ))

    (out_dir / "OWNERS.md").write_text(_render_owners(
        repo_name=repo_name,
        default_owner=default_owner,
        approver_of_last_resort=approver,
        action_types=action_types,
        action_owners=action_owners,
    ))

    live_review_block = _render_live_review_block(live_api_url)
    (out_dir / "review-process.md").write_text(_render_review_process(
        repo_name=repo_name,
        review_action_types=review_action_types,
        live_review_block=live_review_block,
    ))

    (out_dir / "ai-use-inventory.md").write_text(_render_inventory(
        repo_name=repo_name,
        summary=summary,
        inventory_rows=inventory_rows,
    ))

    live_attestation_block = _render_live_attestation_block(live_api_url)
    (out_dir / "SELF-ATTESTATION.md").write_text(_render_attestation(
        summary=summary,
        action_types=action_types,
        live_attestation_block=live_attestation_block,
    ))


# ---------------------------------------------------------------------------
# Renderers — one per artifact. Pure functions; no I/O.
# ---------------------------------------------------------------------------


def _render_policy(
    *,
    repo_name: str,
    scan_iso_date: str,
    summary: RepoSummary,
    action_types: list[str],
    policies_dir: Path,
) -> str:
    return POLICY_SCAFFOLD.format(
        repo_name=repo_name,
        scan_iso_date=scan_iso_date,
        providers_block=_bullet_list(
            summary.llm_providers,
            empty="_No LLM providers detected in this scan._",
        ),
        action_types_block=_bullet_list(
            action_types,
            empty="_No supervised action types detected in this scan._",
        ),
        rules_block=_rules_block(action_types, policies_dir),
        frameworks_block=_bullet_list(
            summary.frameworks,
            empty="_No application frameworks detected in this scan._",
        ),
    )


def _render_owners(
    *,
    repo_name: str,
    default_owner: str,
    approver_of_last_resort: str,
    action_types: list[str],
    action_owners: dict[str, str],
) -> str:
    rows = []
    if action_types:
        rows.append("| Action type | Owner | Approver of last resort |")
        rows.append("|---|---|---|")
        for at in action_types:
            owner = action_owners.get(at, default_owner)
            rows.append(f"| `{at}` | {owner} | {approver_of_last_resort} |")
        table = "\n".join(rows)
    else:
        table = "_No supervised action types detected in this scan._"
    return OWNERS_SCAFFOLD.format(
        repo_name=repo_name,
        default_owner=default_owner,
        approver_of_last_resort=approver_of_last_resort,
        owners_table=table,
    )


def _render_review_process(
    *,
    repo_name: str,
    review_action_types: list[str],
    live_review_block: str,
) -> str:
    return REVIEW_PROCESS_SCAFFOLD.format(
        repo_name=repo_name,
        review_action_types_block=_bullet_list(
            review_action_types,
            empty=(
                "_No action types in this scan ship `review` rules — the "
                "supervisor still records every action in the evidence "
                "chain, but no human review is triggered by default._"
            ),
        ),
        live_review_block=live_review_block,
    )


def _render_inventory(
    *,
    repo_name: str,
    summary: RepoSummary,
    inventory_rows: list[tuple[str, int, str, str, str, str]],
) -> str:
    providers_block = _bullet_list(
        summary.llm_providers,
        empty="_No LLM providers detected in this scan._",
    )
    if inventory_rows:
        lines = [
            "| File | Line | Scanner | SDK | Action type | Snippet |",
            "|---|---|---|---|---|---|",
        ]
        for file_, line, scanner, sdk, action_type, snippet in inventory_rows:
            lines.append(
                f"| `{file_}` | {line} | `{scanner}` | `{sdk}` | "
                f"`{action_type}` | `{snippet}` |"
            )
        table = "\n".join(lines)
    else:
        table = (
            "_No AI / LLM / MCP / agent-orchestrator call-sites detected in "
            "this scan._"
        )
    return INVENTORY_SCAFFOLD.format(
        repo_name=repo_name,
        providers_block=providers_block,
        inventory_table=table,
    )


def _render_attestation(
    *,
    summary: RepoSummary,
    action_types: list[str],
    live_attestation_block: str,
) -> str:
    return ATTESTATION_SCAFFOLD.format(
        provider_count_phrase=_count_phrase(
            len(summary.llm_providers), "LLM provider", "LLM providers"
        ),
        action_type_count_phrase=_count_phrase(
            len(action_types), "action type", "action types"
        ),
        live_attestation_block=live_attestation_block,
    )


# ---------------------------------------------------------------------------
# Helpers — owners override, action-type derivation, rules block, live data.
# ---------------------------------------------------------------------------


def _action_types(findings: Sequence[Finding]) -> list[str]:
    """Sorted unique action_types from findings, with `other` removed.

    `other` is excluded because (a) it isn't a policy bucket — the scanner
    uses it for unclassified finds, and (b) listing it as an owned action
    type confuses the questionnaire reader.
    """
    seen = {f.suggested_action_type for f in findings}
    return sorted(at for at in seen if at and at != "other")


def _review_action_types(
    action_types: Sequence[str], policies_dir: Path
) -> list[str]:
    """Subset of action_types whose shipped policy YAML has at least one
    `action: review` rule. These are the action types the customer's queue
    will see at runtime."""
    out: list[str] = []
    for at in action_types:
        src = policies_dir / f"{at}.base.v1.yaml"
        if not src.exists():
            continue
        try:
            data = yaml.safe_load(src.read_text())
        except (yaml.YAMLError, OSError):
            continue
        for rule in (data or {}).get("rules") or []:
            if str(rule.get("action", "")).lower() == "review":
                out.append(at)
                break
    return out


def _rules_block(action_types: Sequence[str], policies_dir: Path) -> str:
    """Render the per-action_type rule list. Reads the YAML straight from
    `policies_dir` (already populated by the generator one step earlier)."""
    if not action_types:
        return "_No policy rules to render — no supervised action types in this scan._"
    sections: list[str] = []
    for at in action_types:
        src = policies_dir / f"{at}.base.v1.yaml"
        if not src.exists():
            sections.append(
                f"### `{at}`\n\n_Policy YAML not shipped for this action type — "
                f"see `runtime-supervisor/policies/`._"
            )
            continue
        try:
            data = yaml.safe_load(src.read_text()) or {}
        except (yaml.YAMLError, OSError):
            sections.append(f"### `{at}`\n\n_Could not parse `{src.name}`._")
            continue
        rules = data.get("rules") or []
        if not rules:
            sections.append(f"### `{at}`\n\n_No rules defined in `{src.name}`._")
            continue
        section = [f"### `{at}` — {len(rules)} rule(s)"]
        for rule in rules:
            rule_id = rule.get("id", "?")
            action = str(rule.get("action", "?")).upper()
            reason = rule.get("reason") or rule.get("explanation") or ""
            reason = " ".join(str(reason).split())  # collapse YAML > folds
            section.append(f"- **{action}** `{rule_id}` — {reason}")
        sections.append("\n".join(section))
    return "\n\n".join(sections)


def _inventory_rows(
    findings: Sequence[Finding], repo_root: Path | None
) -> list[tuple[str, int, str, str, str, str]]:
    """Return (file, line, scanner, sdk, action_type, snippet) tuples for
    every LLM/MCP/agent-orchestrator finding, sorted by file then line."""
    rows: list[tuple[str, int, str, str, str, str]] = []
    for f in findings:
        if f.scanner not in LLM_SCANNERS:
            continue
        file_ = _short_path(f.file, repo_root)
        sdk = str((f.extra or {}).get("sdk") or (f.extra or {}).get("kind") or "—")
        snippet = (f.snippet or "").strip().replace("`", "'")
        if len(snippet) > 80:
            snippet = snippet[:77] + "…"
        rows.append((file_, f.line, f.scanner, sdk, f.suggested_action_type or "—", snippet))
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    return rows


def _load_owners_overrides(
    repo_root: Path | None, owners_config_path: Path | None
) -> dict[str, Any]:
    """Read `<repo_root>/owners.config.yaml` (or the explicit override path)
    and return its parsed dict. Missing file → empty dict. Malformed file →
    empty dict (silent — the artifact still renders with defaults)."""
    candidate: Path | None = None
    if owners_config_path is not None:
        candidate = owners_config_path
    elif repo_root is not None:
        candidate = repo_root / "owners.config.yaml"
    if candidate is None or not candidate.is_file():
        return {}
    try:
        data = yaml.safe_load(candidate.read_text())
    except (yaml.YAMLError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _git_user_email(repo_root: Path | None) -> str:
    """Best-effort `git config --get user.email`. Falls back to the placeholder
    the OWNERS scaffold instructs the customer to fill in."""
    if repo_root is None:
        return "_set in owners.config.yaml_"
    if not shutil.which("git"):
        return "_set in owners.config.yaml_"
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "config", "--get", "user.email"],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "_set in owners.config.yaml_"
    email = (out.stdout or "").strip()
    return email or "_set in owners.config.yaml_"


def _bullet_list(items: Iterable[str], *, empty: str) -> str:
    items = [i for i in items if i]
    if not items:
        return empty
    return "\n".join(f"- {i}" for i in items)


def _count_phrase(n: int, singular: str, plural: str) -> str:
    """`0 LLM providers`, `1 LLM provider`, `5 LLM providers`. Used in the
    attestation so the "Yes" lines read naturally regardless of count.

    Counts are real — pulled from the same `summary`/`findings` that drive
    the linked artifact — so this is NOT a hardcoded literal. The integer
    itself comes from `len(summary.llm_providers)` etc.
    """
    return f"{n} {singular}" if n == 1 else f"{n} {plural}"


def _short_path(path: str, repo_root: Path | None) -> str:
    if repo_root is None:
        return path
    try:
        return str(Path(path).resolve().relative_to(repo_root.resolve()))
    except (OSError, ValueError):
        return path


# ---------------------------------------------------------------------------
# Live-data fetches — best-effort, silent fallback.
# ---------------------------------------------------------------------------


def _render_live_review_block(live_api_url: str | None) -> str:
    """Optional supervisor-API snapshot appended to review-process.md.

    Without a URL we render nothing (the artifact already cites the
    endpoints by name). With a URL we try to add a one-line "resolved in
    the last 90 days: N" — and fall back to nothing on any error.
    """
    if not live_api_url:
        return ""
    since = (_dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=90)).isoformat()
    data = _http_get_json(
        f"{live_api_url.rstrip('/')}/v1/review-cases"
        f"?status=resolved&since={since}"
    )
    if data is None:
        return ""
    if isinstance(data, dict):
        items = data.get("items") or data.get("cases") or data.get("results") or []
        count = data.get("count") if isinstance(data.get("count"), int) else len(items)
    elif isinstance(data, list):
        count = len(data)
    else:
        return ""
    return (
        "\n## Live snapshot\n\n"
        f"- Resolved review items in the last 90 days: **{count}**\n"
        f"- Source: `GET /v1/review-cases?status=resolved&since=<now-90d>` on "
        f"`{live_api_url}`\n"
    )


def _render_live_attestation_block(live_api_url: str | None) -> str:
    """Optional live-data block appended to SELF-ATTESTATION.md."""
    if not live_api_url:
        return ""
    data = _http_get_json(
        f"{live_api_url.rstrip('/')}/v1/actions?limit=5&with_evidence_status=true"
    )
    if data is None:
        return ""
    rows: list[dict[str, Any]]
    if isinstance(data, dict):
        rows = data.get("items") or data.get("actions") or []
    elif isinstance(data, list):
        rows = data
    else:
        return ""
    if not rows:
        return ""
    lines = [
        "\n## Live evidence-chain spot-check",
        "",
        "Last 5 actions returned by the supervisor — each evidence chain "
        "verified at fetch time:",
        "",
        "| Action ID | Verify result |",
        "|---|---|",
    ]
    for row in rows[:5]:
        if not isinstance(row, dict):
            continue
        action_id = str(row.get("id") or row.get("action_id") or "—")
        ok = row.get("evidence_verified")
        verdict = "ok" if ok is True else ("FAIL" if ok is False else "—")
        lines.append(f"| `{action_id}` | `{verdict}` |")
    lines.append("")
    lines.append(f"_Source: `GET /v1/actions?limit=5&with_evidence_status=true` "
                 f"on `{live_api_url}`._")
    return "\n".join(lines)


def _http_get_json(url: str, *, timeout: float = 2.0) -> Any:
    """Tiny stdlib JSON fetcher. Returns None on any error so callers can
    fall back to the offline rendering without surfacing the failure."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                return None
            payload = resp.read().decode("utf-8", errors="replace")
            return json.loads(payload)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None
