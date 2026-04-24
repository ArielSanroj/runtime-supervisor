"""Golden-repo regression snapshots.

Each entry in `_REPOS` pins a public repo at a specific commit SHA. The test
clones it (cached under `/tmp/supervisor_discover_golden_cache/`), runs the
full scanner pipeline, normalizes the output, and compares against a committed
JSON snapshot in `tests/golden_repos/<name>@<sha8>.json`.

**What the snapshot asserts**: total count, per-scanner counts, high-confidence
count, and the full list of findings — with rationale strings, snippets, and
absolute paths stripped so the snapshot is stable across machines.

**What the snapshot ignores**: rationale text (can be edited without being a
regression), snippets (already indirectly covered by file:line).

**How to update a snapshot**: when the scanner intentionally changes
(new detector, promoted confidence, etc.), delete the affected
`tests/golden_repos/*.json` file and re-run pytest once — the test auto-records
the new baseline, and it's then committed as the new "correct" output.
"""
from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from supervisor_discover.scanners import scan_all

_GOLDEN_DIR = Path(__file__).parent / "golden_repos"
_CACHE_DIR = Path("/tmp/supervisor_discover_golden_cache")

_REPOS: list[dict[str, str]] = [
    {
        "name": "ml-intern",
        "url": "https://github.com/huggingface/ml-intern",
        "sha": "4e4cabffefc226dc3eb71018105090fdd3d7bf85",
    },
]


def _ensure_clone(repo: dict[str, str]) -> Path:
    """Clone the repo at the pinned SHA, caching under /tmp."""
    short_sha = repo["sha"][:8]
    clone_dir = _CACHE_DIR / f"{repo['name']}@{short_sha}"
    if clone_dir.exists() and (clone_dir / ".git").exists():
        return clone_dir
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    # Shallow clone + SHA checkout. Shallow is faster; the SHA anchor protects
    # us against `main` drifting between machines.
    subprocess.run(
        ["git", "clone", "--quiet", repo["url"], str(clone_dir)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(clone_dir), "checkout", "--quiet", repo["sha"]],
        check=True,
        capture_output=True,
    )
    return clone_dir


def _normalize(findings, repo_root: Path) -> dict:
    """Strip volatile fields and sort deterministically so snapshots are
    reproducible across machines (path prefix differs, findings order can
    shift depending on filesystem walk order)."""
    root_variants = [str(repo_root) + "/", str(repo_root.resolve()) + "/"]
    compact: list[dict] = []
    for f in findings:
        file_rel = f.file
        for root_str in root_variants:
            if file_rel.startswith(root_str):
                file_rel = file_rel[len(root_str):]
                break
        extra = f.extra or {}
        compact.append({
            "scanner": f.scanner,
            "file": file_rel,
            "line": f.line,
            "confidence": f.confidence,
            "suggested_action_type": f.suggested_action_type,
            "family": extra.get("family") or extra.get("kind") or extra.get("provider"),
            "method_name": extra.get("method_name"),
            "class_name": extra.get("class_name"),
            "downgraded_eval_path": bool(extra.get("downgraded_eval_path", False)),
        })

    compact.sort(key=lambda d: (
        d["scanner"], d["file"], d["line"],
        d.get("family") or "", d.get("method_name") or "",
    ))

    scanner_counts = dict(Counter(f["scanner"] for f in compact))
    high_count = sum(1 for f in compact if f["confidence"] == "high")

    return {
        "total": len(compact),
        "scanner_counts": scanner_counts,
        "high_confidence": high_count,
        "findings": compact,
    }


def _snapshot_path(repo: dict[str, str]) -> Path:
    return _GOLDEN_DIR / f"{repo['name']}@{repo['sha'][:8]}.json"


@pytest.mark.parametrize("repo", _REPOS, ids=lambda r: r["name"])
def test_golden_snapshot_matches(repo: dict[str, str]) -> None:
    """The scanner output for each pinned repo must match the committed
    snapshot. A failure here means some scanner change altered how real
    repos are reported — review the diff and either fix the bug or (if
    intentional) delete the stale snapshot file to let the test re-record."""
    try:
        clone_dir = _ensure_clone(repo)
    except subprocess.CalledProcessError as e:
        pytest.skip(f"could not clone {repo['url']}: {e}")
        return

    actual = {
        "repo": repo["url"].split("github.com/")[-1],
        "sha": repo["sha"],
        **_normalize(scan_all(clone_dir), clone_dir),
    }

    path = _snapshot_path(repo)
    if not path.exists():
        # First run: lay down the baseline. No assertion — the next run compares.
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
        pytest.skip(f"recorded new golden snapshot at {path.name}")
        return

    expected = json.loads(path.read_text())
    assert actual == expected, (
        f"\n\nScanner output drifted from golden snapshot {path.name}.\n"
        f"If the change is INTENTIONAL (new detector, promoted confidence, etc.):\n"
        f"  rm {path}\n"
        f"  pytest {Path(__file__).name}  # re-records\n"
        f"Then commit the new snapshot.\n\n"
        f"Expected total: {expected['total']}, actual total: {actual['total']}\n"
        f"Expected scanner_counts: {expected['scanner_counts']}\n"
        f"Actual scanner_counts:   {actual['scanner_counts']}\n"
    )
