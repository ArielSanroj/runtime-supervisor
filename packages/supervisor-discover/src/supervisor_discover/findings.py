"""Common finding shape."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Confidence = Literal["low", "medium", "high"]


# Whitespace, common comment prefixes, and trailing punctuation are noise
# we strip from the snippet before hashing — without this, an unrelated
# reformat on the same line would change the finding's stable id.
_NORMALIZE_RE = re.compile(r"\s+")


def _normalize_snippet(snippet: str) -> str:
    """Drop ALL whitespace, lowercase, strip trailing punctuation.

    The ID stays stable across:
      - reformatting (black / prettier — removes/adds spaces inside calls)
      - case differences in keywords (rare, but cheap to absorb)
      - trailing commas / parens added by an extra arg

    What still changes the ID:
      - the call's identifier (e.g. `subprocess.run` → `subprocess.Popen`)
      - the constant string args (e.g. `requests.get("https://x")` →
        `requests.get("https://y")`) — those are different findings.
      - quote style is preserved (`'x'` vs `"x"` produce different IDs);
        upgrade with a future quote-normalization pass if it matters.
    """
    s = _NORMALIZE_RE.sub("", snippet.lower())
    while s and s[-1] in ",;.":
        s = s[:-1]
    return s


def _short_path(path: str, repo_root: Path | None = None) -> str:
    """Return path relative to repo_root when possible, else the basename
    plus parent dir. Used so finding IDs survive a repo move (e.g. cloned
    into a different parent dir between two scans)."""
    if repo_root is not None:
        try:
            return str(Path(path).resolve().relative_to(repo_root.resolve()))
        except (OSError, ValueError):
            pass
    parts = Path(path).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else Path(path).name


def stable_id(scanner: str, file: str, line: int, snippet: str,
              repo_root: Path | None = None) -> str:
    """Deterministic id for a finding. 12-char hex hash of
    (scanner, normalized-relative-file, line, normalized-snippet).

    Used by `supervisor-discover diff` to match findings across two scans
    even when the repo was reformatted, comments above the call were
    edited, or the scan was run from a different working directory.
    """
    rel = _short_path(file, repo_root)
    payload = "|".join((scanner, rel, str(line), _normalize_snippet(snippet)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


@dataclass
class Finding:
    scanner: str          # "http-routes" | "llm-calls" | "payment-calls" | "db-mutations" | "cron-schedules"
    file: str             # absolute path
    line: int             # 1-indexed
    snippet: str          # short code fragment
    suggested_action_type: str  # "refund" | "payment" | "account_change" | "data_access" | "tool_use" | "compliance" | "other"
    confidence: Confidence
    rationale: str
    extra: dict[str, Any] = field(default_factory=dict)
    id: str = ""          # populated by `assign_ids` after scanning; "" until then.

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assign_ids(findings: list[Finding], repo_root: Path | None = None) -> list[Finding]:
    """Mutate `findings` in place with a stable id derived from
    (scanner, file relative to repo_root, line, normalized snippet).

    Run once after `scan_all` finishes; idempotent for the same inputs.
    """
    for f in findings:
        f.id = stable_id(f.scanner, f.file, f.line, f.snippet, repo_root)
    return findings
