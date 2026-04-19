"""`supervisor-discover` CLI entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .classifier import validate
from .generator import generate
from .scanners import scan_all


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

    findings = validate(scan_all(root))

    if dry_run:
        json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    generate(findings, out)
    print(f"wrote {len(findings)} findings to {out}", file=sys.stderr)
    print(f"see {out / 'report.md'} for next steps", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
