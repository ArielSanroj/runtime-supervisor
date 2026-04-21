"""`supervisor-discover` CLI entry point."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .classifier import TIER_ORDER, group_by_risk_tier, validate
from .generator import generate
from .scanners import scan_all
from .summary import build_summary, render_cli_stdout
from .templates import TIER_COPY


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="supervisor-discover",
        description="Scan an agent repo to find what the runtime-supervisor should guard.",
    )
    p.add_argument("--version", action="version", version=f"supervisor-discover {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan and optionally write outputs")
    scan_p.add_argument("--path", default=".", help="Repo root to scan (default: cwd)")
    scan_p.add_argument("--out", default="runtime-supervisor", help="Output directory (default: ./runtime-supervisor)")
    scan_p.add_argument("--dry-run", action="store_true", help="Don't write files; print findings.json to stdout")

    sub.add_parser("init", help="Alias for `scan` with defaults that write to ./runtime-supervisor/")

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = Path(args.path if args.cmd == "scan" else ".").resolve()
    out = Path(args.out if args.cmd == "scan" else "runtime-supervisor").resolve()
    dry_run = bool(getattr(args, "dry_run", False))

    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    # Refuse to scan $HOME — the user almost certainly meant a specific project.
    home = Path.home().resolve()
    if root == home:
        print(
            f"refusing to scan your home directory ({root}).\n"
            "cd into the project you want to supervise and re-run, or pass --path /abs/path/to/repo.",
            file=sys.stderr,
        )
        return 2

    t0 = time.perf_counter()
    findings = validate(scan_all(root))
    elapsed = time.perf_counter() - t0

    if dry_run:
        # Mirror the on-disk findings.json shape so CI diffs line up.
        summary = build_summary(findings)
        payload = {
            "repo_summary": summary.to_dict(),
            "findings": sorted(
                (f.to_dict() for f in findings),
                key=lambda d: (d["file"], d["line"], d["scanner"]),
            ),
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    generate(findings, out)
    _print_tier_summary(root, findings, elapsed, out)
    return 0


def _print_tier_summary(root: Path, findings: list, elapsed: float, out: Path) -> None:
    """Repo summary + tier-by-risk on stderr. Replaces the old 'wrote N findings'
    dump so the reader sees what the repo IS and its risk surface counts."""
    buckets = group_by_risk_tier(findings)
    print(f"scanned {root} in {elapsed:.1f}s", file=sys.stderr)
    print("", file=sys.stderr)
    for line in render_cli_stdout(build_summary(findings)):
        print(line, file=sys.stderr)
    print("", file=sys.stderr)
    for tier in TIER_ORDER:
        items = buckets[tier]
        title = TIER_COPY[tier]["title"]
        if tier == "general":
            print(f"  {title:<22s} {len(items)} informational", file=sys.stderr)
            continue
        high = sum(1 for f in items if f.confidence == "high")
        med = sum(1 for f in items if f.confidence == "medium")
        low = sum(1 for f in items if f.confidence == "low")
        print(f"  {title:<22s} {high} high / {med} medium / {low} low", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"-> wrote {out}", file=sys.stderr)
    print(f"-> next: open {out / 'ROLLOUT.md'} for the deploy playbook tailored to this repo", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
